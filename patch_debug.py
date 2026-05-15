import sys

file1 = r'd:\desktop\signal\mySignal\rust\protocol\src\ratchet.rs'
with open(file1, 'r', encoding='utf-8') as f:
    c1 = f.read()

# Alice
target_alice = '''    let (_ss, tkem_ciphertext) =
        their_tkem_master_key.encapsulate_with_tag(&mut csprng, &tag)?;'''
replace_alice = '''    let (_ss, tkem_ciphertext) =
        their_tkem_master_key.encapsulate_with_tag(&mut csprng, &tag)?;
    println!("ALICE init: tag={:?}, ss={:?}", hex::encode(&tag), hex::encode(&_ss));'''
c1 = c1.replace(target_alice.replace('\n', '\r\n'), replace_alice.replace('\n', '\r\n'))

# Bob
target_bob = '''    let tkem_ss = our_tkem_key_pair
        .tagsecret_key
        .decapsulate_with_tag(&their_tkem_ciphertext_box, their_tkem_tag.as_slice())?;'''
replace_bob = '''    let tkem_ss = our_tkem_key_pair
        .tagsecret_key
        .decapsulate_with_tag(&their_tkem_ciphertext_box, their_tkem_tag.as_slice())?;
    println!("BOB init: tag={:?}, ss={:?}", hex::encode(&their_tkem_tag), hex::encode(&tkem_ss));'''
c1 = c1.replace(target_bob.replace('\n', '\r\n'), replace_bob.replace('\n', '\r\n'))

with open(file1, 'w', encoding='utf-8') as f:
    f.write(c1)

file2 = r'd:\desktop\signal\mySignal\rust\protocol\src\session_cipher.rs'
with open(file2, 'r', encoding='utf-8') as f:
    c2 = f.read()

# Alice encrypt
target_enc = '''    let message_keys = chain_key
        .message_keys()
        .generate_keys(pqr_key);'''
replace_enc = '''    let message_keys = chain_key
        .message_keys()
        .generate_keys(pqr_key.clone());
    println!("ALICE enc: pqr_key={:?}, mac_key={:?}", pqr_key.map(|k| hex::encode(k)), hex::encode(message_keys.mac_key()));'''
c2 = c2.replace(target_enc.replace('\n', '\r\n'), replace_enc.replace('\n', '\r\n'))

# Bob decrypt
target_dec = '''    let message_keys = message_key_gen.generate_keys(pqr_key_to_use);'''
replace_dec = '''    let message_keys = message_key_gen.generate_keys(pqr_key_to_use.clone());
    println!("BOB dec: pqr_key={:?}, mac_key={:?}", pqr_key_to_use.map(|k| hex::encode(k)), hex::encode(message_keys.mac_key()));'''
c2 = c2.replace(target_dec.replace('\n', '\r\n'), replace_dec.replace('\n', '\r\n'))

with open(file2, 'w', encoding='utf-8') as f:
    f.write(c2)

print('Done')
