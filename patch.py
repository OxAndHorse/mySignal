import sys

file_path = r'd:\desktop\signal\mySignal\rust\protocol\src\session_cipher.rs'

with open(file_path, 'r', encoding='utf-8') as f:
    content = f.read()

target1 = '''    let remote_tkem_pub = tkem_store.get_remote_tkem_public_key(remote_address).await?.ok_or_else(|| {
        SignalProtocolError::InvalidState("message_encrypt_tkem", "No remote TKEM public key found".into())
    })?;

    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"PQ-TAG");
    hasher.update(sender_ephemeral.serialize()); // EPKA
    hasher.update(their_identity_key.public_key().serialize()); // IPKB
    hasher.update(local_identity_key.public_key().serialize()); // IPKA
    let tag = hasher.finalize();

    let (pqr_key, tkem_ciphertext) = remote_tkem_pub.encapsulate_with_tag(csprng, &tag).map_err(|e| {
        SignalProtocolError::InvalidState("message_encrypt_tkem", format!("TKEM encapsulate failed: {e}"))
    })?;

    let message_keys = chain_key
        .message_keys()
        .generate_keys(Some(pqr_key.into_vec()));'''

replacement1 = '''    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"PQ-TAG");
    hasher.update(sender_ephemeral.serialize()); // EPKA
    hasher.update(their_identity_key.public_key().serialize()); // IPKB
    hasher.update(local_identity_key.public_key().serialize()); // IPKA
    let computed_tag = hasher.finalize();

    let (pqr_key, tkem_ciphertext, tag) = if let Some(_) = session_state.unacknowledged_pre_key_message_items()? {
        let tkem_ct = session_state.get_tkem_ciphertext().unwrap().clone();
        let tkem_t = session_state.get_tkem_tag().unwrap().clone();
        (None, tkem_ct, tkem_t)
    } else {
        let remote_tkem_pub = tkem_store.get_remote_tkem_public_key(remote_address).await?.ok_or_else(|| {
            SignalProtocolError::InvalidState("message_encrypt_tkem", "No remote TKEM public key found".into())
        })?;
        let (ss, ct) = remote_tkem_pub.encapsulate_with_tag(csprng, &computed_tag).map_err(|e| {
            SignalProtocolError::InvalidState("message_encrypt_tkem", format!("TKEM encapsulate failed: {e}"))
        })?;
        (Some(ss.into_vec()), ct.as_ref().to_vec(), computed_tag.to_vec())
    };

    let message_keys = chain_key
        .message_keys()
        .generate_keys(pqr_key);'''

content = content.replace(target1.replace('\n', '\r\n'), replacement1.replace('\n', '\r\n'))

with open(file_path, 'w', encoding='utf-8') as f:
    f.write(content)

print('Done')
