//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::time::SystemTime;

use rand::{CryptoRng, Rng};

use crate::consts::{MAX_FORWARD_JUMPS, MAX_UNACKNOWLEDGED_SESSION_AGE};
use crate::ratchet::{ChainKey, MessageKeyGenerator, UsePQRatchet};
use crate::state::{InvalidSessionError, SessionState};
use crate::{
    session, CiphertextMessage, CiphertextMessageType, Direction, IdentityKeyStore, KeyPair,
    KyberPayload, KyberPreKeyStore, PreKeySignalMessage, PreKeyStore, ProtocolAddress, PublicKey,
    Result, SessionRecord, SessionStore, SignalMessage, SignalProtocolError, SignedPreKeyStore,
};

pub async fn message_encrypt<R: Rng + CryptoRng>(
    ptext: &[u8],
    remote_address: &ProtocolAddress,
    session_store: &mut dyn SessionStore,
    identity_store: &mut dyn IdentityKeyStore,
    now: SystemTime,
    csprng: &mut R,
) -> Result<CiphertextMessage> {
    let mut session_record = session_store
        .load_session(remote_address)
        .await?
        .ok_or_else(|| SignalProtocolError::SessionNotFound(remote_address.clone()))?;
    let session_state = session_record
        .session_state_mut()
        .ok_or_else(|| SignalProtocolError::SessionNotFound(remote_address.clone()))?;

    let chain_key = session_state.get_sender_chain_key()?;

    let (pqr_msg, pqr_key) = session_state.pq_ratchet_send(csprng).map_err(|e| {
        // Since we're sending, this must be an error with the state.
        SignalProtocolError::InvalidState(
            "message_encrypt",
            format!("post-quantum ratchet send error: {e}"),
        )
    })?;
    let message_keys = chain_key.message_keys().generate_keys(pqr_key);
    //这是用于非对称棘轮更新的密钥
    let sender_ephemeral = session_state.sender_ratchet_key()?;
    let previous_counter = session_state.previous_counter();
    let session_version = session_state
        .session_version()?
        .try_into()
        .map_err(|_| SignalProtocolError::InvalidSessionStructure("version does not fit in u8"))?;

    let local_identity_key = session_state.local_identity_key()?;
    let their_identity_key = session_state.remote_identity_key()?.ok_or_else(|| {
        SignalProtocolError::InvalidState(
            "message_encrypt",
            format!("no remote identity key for {remote_address}"),
        )
    })?;

    let ctext =
        signal_crypto::aes_256_cbc_encrypt(ptext, message_keys.cipher_key(), message_keys.iv())
            .map_err(|_| {
                log::error!("session state corrupt for {remote_address}");
                SignalProtocolError::InvalidSessionStructure("invalid sender chain message keys")
            })?;

    let message = if let Some(items) = session_state.unacknowledged_pre_key_message_items()? {
        let timestamp_as_unix_time = items
            .timestamp()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if items.timestamp() + MAX_UNACKNOWLEDGED_SESSION_AGE < now {
            log::warn!(
                "stale unacknowledged session for {remote_address} (created at {timestamp_as_unix_time})"
            );
            return Err(SignalProtocolError::SessionNotFound(remote_address.clone()));
        }

        let local_registration_id = session_state.local_registration_id();

        log::info!(
            "Building PreKeyWhisperMessage for: {} with preKeyId: {} (session created at {})",
            remote_address,
            items
                .pre_key_id()
                .map_or_else(|| "<none>".to_string(), |id| id.to_string()),
            timestamp_as_unix_time,
        );

        let message = SignalMessage::new(
            session_version,
            message_keys.mac_key(),
            sender_ephemeral,
            chain_key.index(),
            previous_counter,
            &ctext,
            &local_identity_key,
            &their_identity_key,
            &pqr_msg,
        )?;
        //  Kyber PreKey ID + 密文
        let kyber_payload = items
            .kyber_pre_key_id()
            .zip(items.kyber_ciphertext())
            .map(|(id, ciphertext)| KyberPayload::new(id, ciphertext.into()));

        CiphertextMessage::PreKeySignalMessage(PreKeySignalMessage::new(
            session_version,
            local_registration_id,
            items.pre_key_id(),
            items.signed_pre_key_id(),
            kyber_payload,
            *items.base_key(),
            local_identity_key,
            message,
        )?)
    } else {
        CiphertextMessage::SignalMessage(SignalMessage::new(
            session_version,
            message_keys.mac_key(),
            sender_ephemeral,
            chain_key.index(),
            previous_counter,
            &ctext,
            &local_identity_key,
            &their_identity_key,
            &pqr_msg,
        )?)
    };
    //推进发送链
    session_state.set_sender_chain_key(&chain_key.next_chain_key());

    // XXX why is this check after everything else?!!
    if !identity_store
        .is_trusted_identity(remote_address, &their_identity_key, Direction::Sending)
        .await?
    {
        log::warn!(
            "Identity key {} is not trusted for remote address {}",
            hex::encode(their_identity_key.public_key().public_key_bytes()),
            remote_address,
        );
        return Err(SignalProtocolError::UntrustedIdentity(
            remote_address.clone(),
        ));
    }

    // XXX this could be combined with the above call to the identity store (in a new API)
    identity_store
        .save_identity(remote_address, &their_identity_key)
        .await?;

    session_store
        .store_session(remote_address, &session_record)
        .await?;
    Ok(message)
}

#[allow(clippy::too_many_arguments)]
pub async fn message_decrypt<R: Rng + CryptoRng>(
    ciphertext: &CiphertextMessage,
    remote_address: &ProtocolAddress,
    session_store: &mut dyn SessionStore,
    identity_store: &mut dyn IdentityKeyStore,
    pre_key_store: &mut dyn PreKeyStore,
    signed_pre_key_store: &dyn SignedPreKeyStore,
    kyber_pre_key_store: &mut dyn KyberPreKeyStore,
    csprng: &mut R,
    use_pq_ratchet: UsePQRatchet,
) -> Result<Vec<u8>> {
    match ciphertext {
        CiphertextMessage::SignalMessage(m) => {
            message_decrypt_signal(m, remote_address, session_store, identity_store, csprng).await
        }
        CiphertextMessage::PreKeySignalMessage(m) => {
            message_decrypt_prekey(
                m,
                remote_address,
                session_store,
                identity_store,
                pre_key_store,
                signed_pre_key_store,
                kyber_pre_key_store,
                csprng,
                use_pq_ratchet,
            )
            .await
        }
        _ => Err(SignalProtocolError::InvalidArgument(format!(
            "message_decrypt cannot be used to decrypt {:?} messages",
            ciphertext.message_type()
        ))),
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn message_decrypt_prekey<R: Rng + CryptoRng>(
    ciphertext: &PreKeySignalMessage,
    remote_address: &ProtocolAddress,
    session_store: &mut dyn SessionStore,
    identity_store: &mut dyn IdentityKeyStore,
    pre_key_store: &mut dyn PreKeyStore,
    signed_pre_key_store: &dyn SignedPreKeyStore,
    kyber_pre_key_store: &mut dyn KyberPreKeyStore,
    csprng: &mut R,
    use_pq_ratchet: UsePQRatchet,
) -> Result<Vec<u8>> {
    //1. 加载或创建会话记录
    let mut session_record = session_store
        .load_session(remote_address)
        .await?
        .unwrap_or_else(SessionRecord::new_fresh);//没有就新创建
    //返回被使用的 pre_key_id 和 kyber_pre_key_id，用于后续清理。
    // Make sure we log the session state if we fail to process the pre-key.

    //2。处理prekey信息
    //     这是 最关键的一步，内部通常执行以下操作：

    // ✅ X3DH / PQXDH 密钥协商（根据 use_pq_ratchet）：
    // 验证对方的 身份公钥（Identity Key） 签名。
    // 验证 Signed PreKey 的签名（防篡改）。
    // （若启用 PQ）验证 Kyber PreKey。
    // 执行多轮 DH 计算，派生出 初始根密钥（Root Key） 和 发送/接收链初始状态。
    // 构建完整的 SessionState 并存入 session_record。
    let process_prekey_result = session::process_prekey(
        ciphertext,
        remote_address,
        &mut session_record,
        identity_store,
        pre_key_store,
        signed_pre_key_store,
        kyber_pre_key_store,
        use_pq_ratchet,
    )
    .await;



    let (pre_key_used, identity_to_save) = match process_prekey_result {
        Ok(result) => result,
        Err(e) => {
            let errs = [e];
            log::error!(
                "{}",
                create_decryption_failure_log(
                    remote_address,
                    &errs,
                    &session_record,
                    ciphertext.message()
                )?
            );
            let [e] = errs;
            return Err(e);//结束
        }
    };

    //调用通用解密函数，传入刚初始化的 session_record。
    // 内部会：
    // 从 SessionState 中获取接收链密钥；
    // 根据消息中的 counter（消息序号）派生 MessageKey；
    // 使用 AES-GCM / AES-CBC + HMAC 解密消息体；
    // 更新接收链状态（推进链索引）。
    let ptext = decrypt_message_with_record(
        remote_address,
        &mut session_record,
        ciphertext.message(),
        CiphertextMessageType::PreKey,
        csprng,
    )?;
// 保存身份：将对方的身份公钥与地址绑定，用于未来消息的身份验证（防止中间人攻击）。
// 保存会话：将新建立或更新的会话状态写回存储，供后续消息使用。
    identity_store
        .save_identity(
            identity_to_save.remote_address,
            identity_to_save.their_identity_key,
        )
        .await?;

    session_store
        .store_session(remote_address, &session_record)
        .await?;
    //     一次性预密钥（PreKey） 只能使用一次，用完即删，保证前向保密。
    // Kyber 预密钥 同理，标记为“已使用”（可能延迟删除，但不再用于新会话）。
    if let Some(pre_key_id) = pre_key_used.pre_key_id {
        pre_key_store.remove_pre_key(pre_key_id).await?;
    }
    //
    if let Some(kyber_pre_key_id) = pre_key_used.kyber_pre_key_id {
        kyber_pre_key_store
            .mark_kyber_pre_key_used(kyber_pre_key_id)
            .await?;
    }

    Ok(ptext)
}

pub async fn message_decrypt_signal<R: Rng + CryptoRng>(
    ciphertext: &SignalMessage,
    remote_address: &ProtocolAddress,
    session_store: &mut dyn SessionStore,
    identity_store: &mut dyn IdentityKeyStore,
    csprng: &mut R,
) -> Result<Vec<u8>> {
    let mut session_record = session_store
        .load_session(remote_address)
        .await?
        .ok_or_else(|| SignalProtocolError::SessionNotFound(remote_address.clone()))?;

    let ptext = decrypt_message_with_record(
        remote_address,
        &mut session_record,
        ciphertext,
        CiphertextMessageType::Whisper,
        csprng,
    )?;

    // Why are we performing this check after decryption instead of before?
    let their_identity_key = session_record
        .session_state()
        .expect("successfully decrypted; must have a current state")
        .remote_identity_key()
        .expect("successfully decrypted; must have a remote identity key")
        .expect("successfully decrypted; must have a remote identity key");

    if !identity_store
        .is_trusted_identity(remote_address, &their_identity_key, Direction::Receiving)
        .await?
    {
        log::warn!(
            "Identity key {} is not trusted for remote address {}",
            hex::encode(their_identity_key.public_key().public_key_bytes()),
            remote_address,
        );
        return Err(SignalProtocolError::UntrustedIdentity(
            remote_address.clone(),
        ));
    }

    identity_store
        .save_identity(remote_address, &their_identity_key)
        .await?;

    session_store
        .store_session(remote_address, &session_record)
        .await?;

    Ok(ptext)
}

fn create_decryption_failure_log(
    remote_address: &ProtocolAddress,
    mut errs: &[SignalProtocolError],
    record: &SessionRecord,
    ciphertext: &SignalMessage,
) -> Result<String> {
    fn append_session_summary(
        lines: &mut Vec<String>,
        idx: usize,
        state: std::result::Result<&SessionState, InvalidSessionError>,
        err: Option<&SignalProtocolError>,
    ) {
        let chains = state.map(|state| state.all_receiver_chain_logging_info());
        match (err, &chains) {
            (Some(err), Ok(chains)) => {
                lines.push(format!(
                    "Candidate session {} failed with '{}', had {} receiver chains",
                    idx,
                    err,
                    chains.len()
                ));
            }
            (Some(err), Err(state_err)) => {
                lines.push(format!(
                    "Candidate session {idx} failed with '{err}'; cannot get receiver chain info ({state_err})",
                ));
            }
            (None, Ok(chains)) => {
                lines.push(format!(
                    "Candidate session {} had {} receiver chains",
                    idx,
                    chains.len()
                ));
            }
            (None, Err(state_err)) => {
                lines.push(format!(
                    "Candidate session {idx}: cannot get receiver chain info ({state_err})",
                ));
            }
        }

        if let Ok(chains) = chains {
            for chain in chains {
                let chain_idx = match chain.1 {
                    Some(i) => i.to_string(),
                    None => "missing in protobuf".to_string(),
                };

                lines.push(format!(
                    "Receiver chain with sender ratchet public key {} chain key index {}",
                    hex::encode(chain.0),
                    chain_idx
                ));
            }
        }
    }

    let mut lines = vec![];

    lines.push(format!(
        "Message from {} failed to decrypt; sender ratchet public key {} message counter {}",
        remote_address,
        hex::encode(ciphertext.sender_ratchet_key().public_key_bytes()),
        ciphertext.counter()
    ));

    if let Some(current_session) = record.session_state() {
        let err = errs.first();
        if err.is_some() {
            errs = &errs[1..];
        }
        append_session_summary(&mut lines, 0, Ok(current_session), err);
    } else {
        lines.push("No current session".to_string());
    }

    for (idx, (state, err)) in record
        .previous_session_states()
        .zip(errs.iter().map(Some).chain(std::iter::repeat(None)))
        .enumerate()
    {
        let state = match state {
            Ok(ref state) => Ok(state),
            Err(err) => Err(err),
        };
        append_session_summary(&mut lines, idx + 1, state, err);
    }

    Ok(lines.join("\n"))
}

/*
record: 包含 当前会话状态 + 多个历史会话状态 的会话记录（SessionRecord）。
ciphertext: 要解密的加密消息（SignalMessage，内含 sender_ratchet_key, counter, ciphertext 等）。
original_message_type: 消息原始类型（PreKey 或 Whisper），用于错误上下文


先尝试用当前会话状态解密
成功 → 更新状态并返回明文。
失败但非“重复消息” → 记录错误，继续。
是 DuplicatedMessage → 立即返回（不重试旧会话）。
若当前会话失败，遍历所有历史会话状态（previous sessions）
逐个尝试解密。
成功 → 将该历史会话 提升为当前会话（promote_old_session）。
全部失败 → 报错。
统一错误处理：生成详细日志，返回 InvalidMessage

*/
fn decrypt_message_with_record<R: Rng + CryptoRng>(
    remote_address: &ProtocolAddress,
    record: &mut SessionRecord,
    ciphertext: &SignalMessage,
    original_message_type: CiphertextMessageType,
    csprng: &mut R,
) -> Result<Vec<u8>> {
    debug_assert!(matches!(
        original_message_type,
        CiphertextMessageType::Whisper | CiphertextMessageType::PreKey
    ));
    let log_decryption_failure = |state: &SessionState, error: &SignalProtocolError| {
        // A warning rather than an error because we try multiple sessions.
        log::warn!(
            "Failed to decrypt {:?} message with ratchet key: {} and counter: {}. \
             Session loaded for {}. Local session has base key: {} and counter: {}. {}",
            original_message_type,
            hex::encode(ciphertext.sender_ratchet_key().public_key_bytes()),
            ciphertext.counter(),
            remote_address,
            state
                .sender_ratchet_key_for_logging()
                .unwrap_or_else(|e| format!("<error: {e}>")),
            state.previous_counter(),
            error
        );
    };

    let mut errs = vec![];

    if let Some(current_state) = record.session_state() {
        let mut current_state = current_state.clone();
        let result = decrypt_message_with_state(
            CurrentOrPrevious::Current,
            &mut current_state,
            ciphertext,
            original_message_type,
            remote_address,
            csprng,
        );

        match result {
            Ok(ptext) => {
                log::info!(
                    "decrypted {:?} message from {} with current session state (base key {})",
                    original_message_type,
                    remote_address,
                    current_state
                        .sender_ratchet_key_for_logging()
                        .expect("successful decrypt always has a valid base key"),
                );
                record.set_session_state(current_state); // update the state
                return Ok(ptext);
            }
            Err(SignalProtocolError::DuplicatedMessage(_, _)) => {
                return result;
            }
            Err(e) => {
                log_decryption_failure(&current_state, &e);
                errs.push(e);
                match original_message_type {
                    CiphertextMessageType::PreKey => {
                        // A PreKey message creates a session and then decrypts a Whisper message
                        // using that session. No need to check older sessions.
                        log::error!(
                            "{}",
                            create_decryption_failure_log(
                                remote_address,
                                &errs,
                                record,
                                ciphertext
                            )?
                        );
                        // Note that we don't propagate `e` here; we always return InvalidMessage,
                        // as we would for a Whisper message that tried several sessions.
                        return Err(SignalProtocolError::InvalidMessage(
                            original_message_type,
                            "decryption failed",
                        ));
                    }
                    CiphertextMessageType::Whisper => {}
                    CiphertextMessageType::SenderKey | CiphertextMessageType::Plaintext => {
                        unreachable!("should not be using Double Ratchet for these")
                    }
                }
            }
        }
    }

    // Try some old sessions:
    let mut updated_session = None;

    for (idx, previous) in record.previous_session_states().enumerate() {
        let mut previous = previous?;

        let result = decrypt_message_with_state(
            CurrentOrPrevious::Previous,
            &mut previous,
            ciphertext,
            original_message_type,
            remote_address,
            csprng,
        );

        match result {
            Ok(ptext) => {
                log::info!(
                    "decrypted {:?} message from {} with PREVIOUS session state (base key {})",
                    original_message_type,
                    remote_address,
                    previous
                        .sender_ratchet_key_for_logging()
                        .expect("successful decrypt always has a valid base key"),
                );
                updated_session = Some((ptext, idx, previous));
                break;
            }
            Err(SignalProtocolError::DuplicatedMessage(_, _)) => {
                return result;
            }
            Err(e) => {
                log_decryption_failure(&previous, &e);
                errs.push(e);
            }
        }
    }

    if let Some((ptext, idx, updated_session)) = updated_session {
        record.promote_old_session(idx, updated_session);
        Ok(ptext)
    } else {
        let previous_state_count = || record.previous_session_states().len();

        if let Some(current_state) = record.session_state() {
            log::error!(
                "No valid session for recipient: {}, current session base key {}, number of previous states: {}",
                remote_address,
                current_state.sender_ratchet_key_for_logging()
                .unwrap_or_else(|e| format!("<error: {e}>")),
                previous_state_count(),
            );
        } else {
            log::error!(
                "No valid session for recipient: {}, (no current session state), number of previous states: {}",
                remote_address,
                previous_state_count(),
            );
        }
        log::error!(
            "{}",
            create_decryption_failure_log(remote_address, &errs, record, ciphertext)?
        );
        Err(SignalProtocolError::InvalidMessage(
            original_message_type,
            "decryption failed",
        ))
    }
}

#[derive(Clone, Copy)]
enum CurrentOrPrevious {
    Current,
    Previous,
}

impl std::fmt::Display for CurrentOrPrevious {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Current => write!(f, "current"),
            Self::Previous => write!(f, "previous"),
        }
    }
}

fn decrypt_message_with_state<R: Rng + CryptoRng>(
    current_or_previous: CurrentOrPrevious,
    state: &mut SessionState,
    ciphertext: &SignalMessage,
    original_message_type: CiphertextMessageType,
    remote_address: &ProtocolAddress,
    csprng: &mut R,
) -> Result<Vec<u8>> {
    // Check for a completely empty or invalid session state before we do anything else.
    let _ = state.root_key().map_err(|_| {
        SignalProtocolError::InvalidMessage(
            original_message_type,
            "No session available to decrypt",
        )
    })?;

    let ciphertext_version = ciphertext.message_version() as u32;
    if ciphertext_version != state.session_version()? {
        return Err(SignalProtocolError::UnrecognizedMessageVersion(
            ciphertext_version,
        ));
    }

    let their_ephemeral = ciphertext.sender_ratchet_key();
    let counter = ciphertext.counter();
    let chain_key = get_or_create_chain_key(state, their_ephemeral, remote_address, csprng)?;
    let message_key_gen = get_or_create_message_key(
        state,
        their_ephemeral,
        remote_address,
        original_message_type,
        &chain_key,
        counter,
    )?;
    let pqr_key = state
        .pq_ratchet_recv(ciphertext.pq_ratchet())
        .map_err(|e| match e {
            spqr::Error::StateDecode => SignalProtocolError::InvalidState(
                "decrypt_message_with_state",
                format!("post-quantum ratchet error: {e}"),
            ),
            _ => {
                log::info!("post-quantum ratchet error in decrypt_message_with_state: {e}");
                SignalProtocolError::InvalidMessage(
                    original_message_type,
                    "post-quantum ratchet error",
                )
            }
        })?;
    let message_keys = message_key_gen.generate_keys(pqr_key);

    let their_identity_key =
        state
            .remote_identity_key()?
            .ok_or(SignalProtocolError::InvalidSessionStructure(
                "cannot decrypt without remote identity key",
            ))?;

    let mac_valid = ciphertext.verify_mac(
        &their_identity_key,
        &state.local_identity_key()?,
        message_keys.mac_key(),
    )?;

    if !mac_valid {
        return Err(SignalProtocolError::InvalidMessage(
            original_message_type,
            "MAC verification failed",
        ));
    }

    let ptext = match signal_crypto::aes_256_cbc_decrypt(
        ciphertext.body(),
        message_keys.cipher_key(),
        message_keys.iv(),
    ) {
        Ok(ptext) => ptext,
        Err(signal_crypto::DecryptionError::BadKeyOrIv) => {
            log::warn!("{current_or_previous} session state corrupt for {remote_address}",);
            return Err(SignalProtocolError::InvalidSessionStructure(
                "invalid receiver chain message keys",
            ));
        }
        Err(signal_crypto::DecryptionError::BadCiphertext(msg)) => {
            log::warn!("failed to decrypt 1:1 message: {msg}");
            return Err(SignalProtocolError::InvalidMessage(
                original_message_type,
                "failed to decrypt",
            ));
        }
    };

    state.clear_unacknowledged_pre_key_message();

    Ok(ptext)
}

fn get_or_create_chain_key<R: Rng + CryptoRng>(
    state: &mut SessionState,
    their_ephemeral: &PublicKey,
    remote_address: &ProtocolAddress,
    csprng: &mut R,
) -> Result<ChainKey> {
    // 尝试复用已有接收链
    //检查是否已经为该 their_ephemeral 公钥建立过接收链（receiver chain）。
    // 如果存在，直接返回已有的 ChainKey，避免重复派生。
    // 这对应于  Signal 协议中的“乱序消息处理”场景：同一发送方可能在未收到回复前连续发送多条消息，使用相同的临时密钥。
    if let Some(chain) = state.get_receiver_chain_key(their_ephemeral)? {
        log::debug!("{remote_address} has existing receiver chain.");
        return Ok(chain);
    }
    //非对称棘轮被动更新
    log::info!("{remote_address} creating new chains.");
    //  获取当前根密钥和我方临时私钥
    let root_key = state.root_key()?;
    let our_ephemeral = state.sender_ratchet_private_key()?;
    // 与对方公钥执行 DH，派生接收链
    let receiver_chain = root_key.create_chain(their_ephemeral, &our_ephemeral)?;
    // 生成我方新的临时密钥对，并派生发送链
    let our_new_ephemeral = KeyPair::generate(csprng);
    //发送链的根密钥从初始化的接收链导出
    let sender_chain = receiver_chain
        .0
        .create_chain(their_ephemeral, &our_new_ephemeral.private_key)?;
    //重置根密钥
    state.set_root_key(&sender_chain.0);
    //添加接收链
    state.add_receiver_chain(their_ephemeral, &receiver_chain.1);

    let current_index = state.get_sender_chain_key()?.index();
    let previous_index = if current_index > 0 {
        current_index - 1
    } else {
        0
    };
    state.set_previous_counter(previous_index);
    state.set_sender_chain(&our_new_ephemeral, &sender_chain.1);

    Ok(receiver_chain.1)
}

fn get_or_create_message_key(
    state: &mut SessionState,
    their_ephemeral: &PublicKey,
    remote_address: &ProtocolAddress,
    original_message_type: CiphertextMessageType,
    chain_key: &ChainKey,
    counter: u32,
) -> Result<MessageKeyGenerator> {
    let chain_index = chain_key.index();
    //  第一步：检查是否为重复消息（counter < 当前链索引）

    /*
    先尝试从 已缓存的消息密钥表 中查找 counter 对应的密钥。
    若存在 → 返回（允许解密重传消息）。
    若不存在 → 报错 DuplicatedMessage。
    因为按协议，只有最近 MAX_MESSAGE_KEYS 条消息的密钥会被缓存（防存储耗尽）。
    超出缓存范围的“旧消息”无法解密，视为无效或攻击。
     */
    if chain_index > counter {
        return match state.get_message_keys(their_ephemeral, counter)? {
            Some(keys) => Ok(keys),
            None => {
                log::info!("{remote_address} Duplicate message for counter: {counter}");
                Err(SignalProtocolError::DuplicatedMessage(chain_index, counter))
            }
        };
    }

    assert!(chain_index <= counter);

    let jump = (counter - chain_index) as usize;
    // v第二步：检查是否跳号过多（防止 DoS）
    if jump > MAX_FORWARD_JUMPS {
        if state.session_with_self()? {
            log::info!(
                "{remote_address} Jumping ahead {jump} messages (index: {chain_index}, counter: {counter})"
            );
        } else {
            log::error!(
                "{remote_address} Exceeded future message limit: {MAX_FORWARD_JUMPS}, index: {chain_index}, counter: {counter})"
            );
            return Err(SignalProtocolError::InvalidMessage(
                original_message_type,
                "message from too far into the future",
            ));
        }
    }

    let mut chain_key = chain_key.clone();
    // 第三步：向前推进链，派生中间消息密钥
    /*
    从当前 chain_index 开始，逐次派生直到 counter - 1 的所有 MessageKey。
    将这些中间密钥 缓存到 state 中（供可能的乱序消息使用）。
    最终 chain_key 停在 index == counter
     */
    while chain_key.index() < counter {
        let message_keys = chain_key.message_keys();
        state.set_message_keys(their_ephemeral, message_keys)?;
        chain_key = chain_key.next_chain_key();
    }

    state.set_receiver_chain_key(their_ephemeral, &chain_key.next_chain_key())?;
    Ok(chain_key.message_keys())
}
