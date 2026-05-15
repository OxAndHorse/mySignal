import sys

file_path = r'd:\desktop\signal\mySignal\rust\protocol\src\session_cipher.rs'

with open(file_path, 'r', encoding='utf-8') as f:
    content = f.read()

target2 = '''    let pqr_key_raw = tkem_key_pair
        .tagsecret_key
        .decapsulate_with_tag(&tkem_ciphertext, tag)
        .map_err(|e| {
            SignalProtocolError::InvalidState(
                "decrypt_message_with_state",
                format!("TKEM decapsulate failed: {e}"),
            )
        })?;

    let message_keys = message_key_gen.generate_keys(Some(pqr_key_raw.into_vec()));'''

replacement2 = '''    let pqr_key_raw = tkem_key_pair
        .tagsecret_key
        .decapsulate_with_tag(&tkem_ciphertext, tag)
        .map_err(|e| {
            SignalProtocolError::InvalidState(
                "decrypt_message_with_state",
                format!("TKEM decapsulate failed: {e}"),
            )
        })?;

    let pqr_key_to_use = match original_message_type {
        CiphertextMessageType::PreKey => None,
        _ => Some(pqr_key_raw.into_vec()),
    };

    let message_keys = message_key_gen.generate_keys(pqr_key_to_use);'''

content = content.replace(target2.replace('\n', '\r\n'), replacement2.replace('\n', '\r\n'))

with open(file_path, 'w', encoding='utf-8') as f:
    f.write(content)

print('Done')
