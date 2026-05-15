import sys

file_path = r'd:\desktop\signal\mySignal\rust\protocol\src\session_cipher.rs'

with open(file_path, 'r', encoding='utf-8') as f:
    content = f.read()

target_dec = '''    let message_keys = message_key_gen.generate_keys(pqr_key_to_use.clone());
    println!("BOB dec: pqr_key={:?}, mac_key={:?}", pqr_key_to_use.map(|k| hex::encode(k)), hex::encode(message_keys.mac_key()));'''

replace_dec = '''    let message_keys = message_key_gen.generate_keys(pqr_key_to_use);'''

content = content.replace(target_dec.replace('\n', '\r\n'), replace_dec.replace('\n', '\r\n'))

with open(file_path, 'w', encoding='utf-8') as f:
    f.write(content)

print('Done')
