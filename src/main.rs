use base64::{Engine as _, engine::general_purpose};
use bs58;
use poem::{
    IntoResponse, Response, Route, Server, get, handler, http::StatusCode, listener::TcpListener,
    post, web::Json,
};
use serde::{Deserialize, Serialize};
use solana_sdk::{
    instruction::Instruction,
    pubkey::Pubkey,
    signature::{Keypair, Signature},
    signer::Signer,
    system_instruction,
};
use spl_associated_token_account::get_associated_token_address;
use spl_token::instruction::{initialize_mint, mint_to, transfer};
use std::str::FromStr;

#[derive(Serialize, Deserialize)]
struct KeyPairData {
    pub pubkey: String,
    pub secret: String,
}

#[derive(Serialize, Deserialize)]
struct GenerateKeyPairOutput {
    pub success: bool,
    pub data: KeyPairData,
}

#[derive(Debug, Deserialize)]
struct CreateTokenRequest {
    #[serde(rename = "mintAuthority")]
    mint_authority: String,
    mint: String,
    decimals: u8,
}

#[derive(Debug, Deserialize)]
struct MintTokenRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

#[derive(Deserialize)]
struct SignMessageRequest {
    message: String,
    secret: String,
}

#[derive(Debug, Serialize)]
struct CreateTokenResponse {
    success: bool,
    data: TokenInstructionData,
}

#[derive(Debug, Serialize)]
struct TokenInstructionData {
    program_id: String,
    accounts: Vec<AccountMetaSerializable>,
    instruction_data: String,
}

#[derive(Debug, Serialize)]
struct AccountMetaSerializable {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

#[derive(Serialize)]
struct ErrorResponse {
    success: bool,
    error: String,
}

#[derive(Serialize)]
struct SignMessageResponse {
    success: bool,
    data: SignMessageResponseData,
}

#[derive(Serialize)]
struct SignMessageResponseData {
    signature: String,
    public_key: String,
    message: String,
}

#[derive(Deserialize)]
struct VerifyMessageRequest {
    message: String,
    signature: String,
    pubkey: String,
}

#[derive(Serialize)]
struct VerifyMessageResponse {
    success: bool,
    data: VerifyMessageResponseData,
}

#[derive(Serialize)]
struct VerifyMessageResponseData {
    valid: bool,
    message: String,
    pubkey: String,
}

#[derive(Deserialize)]
struct SendSolRequest {
    from: String,
    to: String,
    lamports: u64,
}

#[derive(Debug, Serialize)]
struct SendSolResponse {
    success: bool,
    data: SolInstructionData,
}

#[derive(Debug, Serialize)]
struct SolInstructionData {
    program_id: String,
    accounts: Vec<String>,
    instruction_data: String,
}

#[derive(Deserialize)]
struct SendTokenRequest {
    destination: String,
    mint: String,
    owner: String,
    amount: u64,
}

#[derive(Serialize)]
struct SendTokenResponse {
    success: bool,
    data: TokenTransferInstructionData,
}

#[derive(Debug, Serialize)]
struct TokenTransferInstructionData {
    program_id: String,
    accounts: Vec<TokenAccountMeta>,
    instruction_data: String,
}

#[derive(Debug, Serialize)]
struct TokenAccountMeta {
    pubkey: String,
    #[serde(rename = "isSigner")]
    is_signer: bool,
}

// Constants for validation limits
const MAX_STRING_LENGTH: usize = 1000;
const MAX_MESSAGE_LENGTH: usize = 10000;
const MIN_LAMPORTS: u64 = 1;
const MAX_LAMPORTS: u64 = u64::MAX / 2; // Prevent potential overflow

// Helper function to validate string length
fn validate_string_length(s: &str, max_len: usize) -> bool {
    s.len() <= max_len
}

// Enhanced validation for base58 public key
fn validate_pubkey(pubkey_str: &str) -> Result<Pubkey, String> {
    let trimmed = pubkey_str.trim();

    // Check string length to prevent memory exhaustion
    if !validate_string_length(trimmed, MAX_STRING_LENGTH) {
        return Err("error".to_string());
    }

    if trimmed.is_empty() {
        return Err("error".to_string());
    }

    // Check for non-base58 characters early
    if !trimmed
        .chars()
        .all(|c| "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".contains(c))
    {
        return Err("error".to_string());
    }

    let decoded = bs58::decode(trimmed)
        .into_vec()
        .map_err(|_| "error".to_string())?;

    if decoded.len() != 32 {
        return Err("error".to_string());
    }

    // Additional validation - ensure it's a valid Solana pubkey
    Pubkey::try_from(decoded.as_slice()).map_err(|_| "error".to_string())
}

// Enhanced validation for secret key
fn validate_secret_key(secret_str: &str) -> Result<Keypair, String> {
    let trimmed = secret_str.trim();

    // Check string length
    if !validate_string_length(trimmed, MAX_STRING_LENGTH) {
        return Err("error".to_string());
    }

    if trimmed.is_empty() {
        return Err("error".to_string());
    }

    // Check for non-base58 characters
    if !trimmed
        .chars()
        .all(|c| "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".contains(c))
    {
        return Err("error".to_string());
    }

    let decoded = bs58::decode(trimmed)
        .into_vec()
        .map_err(|_| "error".to_string())?;

    if decoded.len() != 64 {
        return Err("error".to_string());
    }

    Keypair::try_from(decoded.as_slice()).map_err(|_| "error".to_string())
}

// Enhanced validation for base64 signature
fn validate_signature(signature_str: &str) -> Result<Signature, String> {
    let trimmed = signature_str.trim();

    // Check string length
    if !validate_string_length(trimmed, MAX_STRING_LENGTH) {
        return Err("error".to_string());
    }

    if trimmed.is_empty() {
        return Err("error".to_string());
    }

    // Check for valid base64 characters
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
    {
        return Err("error".to_string());
    }

    let decoded = general_purpose::STANDARD
        .decode(trimmed)
        .map_err(|_| "error".to_string())?;

    if decoded.len() != 64 {
        return Err("error".to_string());
    }

    Signature::try_from(decoded).map_err(|_| "error".to_string())
}

// Enhanced message validation
fn validate_message(message: &str) -> Result<(), String> {
    // Check length
    if !validate_string_length(message, MAX_MESSAGE_LENGTH) {
        return Err("error".to_string());
    }

    if message.trim().is_empty() {
        return Err("error".to_string());
    }

    // Check for null bytes and other problematic characters
    if message.contains('\0') {
        return Err("error".to_string());
    }

    Ok(())
}

// Enhanced amount validation
fn validate_amount(amount: u64) -> Result<(), String> {
    if amount == 0 {
        return Err("error".to_string());
    }

    if amount > MAX_LAMPORTS {
        return Err("error".to_string());
    }

    Ok(())
}

// Enhanced decimals validation
fn validate_decimals(decimals: u8) -> Result<(), String> {
    if decimals > 9 {
        return Err("error".to_string());
    }
    Ok(())
}

fn create_error_response() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorResponse {
            success: false,
            error: "Description of error".to_string(),
        }),
    )
        .into_response()
}

fn create_missing_fields_error() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorResponse {
            success: false,
            error: "Missing required fields".to_string(),
        }),
    )
        .into_response()
}

#[handler]
async fn create_token(Json(payload): Json<CreateTokenRequest>) -> Response {
    // Enhanced validation
    if validate_decimals(payload.decimals).is_err() {
        return create_error_response();
    }

    let mint_pubkey = match validate_pubkey(&payload.mint) {
        Ok(pubkey) => pubkey,
        Err(_) => return create_error_response(),
    };

    let mint_authority = match validate_pubkey(&payload.mint_authority) {
        Ok(pubkey) => pubkey,
        Err(_) => return create_error_response(),
    };

    let ix = match initialize_mint(
        &spl_token::id(),
        &mint_pubkey,
        &mint_authority,
        None,
        payload.decimals,
    ) {
        Ok(ix) => ix,
        Err(_) => return create_error_response(),
    };

    let instruction_data = general_purpose::STANDARD.encode(&ix.data);
    let accounts = ix
        .accounts
        .into_iter()
        .map(|meta| AccountMetaSerializable {
            pubkey: meta.pubkey.to_string(),
            is_signer: meta.is_signer,
            is_writable: meta.is_writable,
        })
        .collect();

    let response = CreateTokenResponse {
        success: true,
        data: TokenInstructionData {
            program_id: ix.program_id.to_string(),
            accounts,
            instruction_data,
        },
    };

    Json(response).into_response()
}

#[handler]
async fn mint_token(Json(payload): Json<MintTokenRequest>) -> Response {
    // Enhanced validation
    if validate_amount(payload.amount).is_err() {
        return create_error_response();
    }

    let mint_pubkey = match validate_pubkey(&payload.mint) {
        Ok(pubkey) => pubkey,
        Err(_) => return create_error_response(),
    };

    let destination_pubkey = match validate_pubkey(&payload.destination) {
        Ok(pubkey) => pubkey,
        Err(_) => return create_error_response(),
    };

    let authority_pubkey = match validate_pubkey(&payload.authority) {
        Ok(pubkey) => pubkey,
        Err(_) => return create_error_response(),
    };

    let ix = match mint_to(
        &spl_token::id(),
        &mint_pubkey,
        &destination_pubkey,
        &authority_pubkey,
        &[&authority_pubkey],
        payload.amount,
    ) {
        Ok(ix) => ix,
        Err(_) => return create_error_response(),
    };

    let instruction_data = general_purpose::STANDARD.encode(&ix.data);
    let accounts = ix
        .accounts
        .into_iter()
        .map(|meta| AccountMetaSerializable {
            pubkey: meta.pubkey.to_string(),
            is_signer: meta.is_signer,
            is_writable: meta.is_writable,
        })
        .collect();

    let response = CreateTokenResponse {
        success: true,
        data: TokenInstructionData {
            program_id: ix.program_id.to_string(),
            accounts,
            instruction_data,
        },
    };

    Json(response).into_response()
}

#[handler]
async fn sign_message(Json(payload): Json<SignMessageRequest>) -> Response {
    // Enhanced validation
    if validate_message(&payload.message).is_err() || payload.secret.trim().is_empty() {
        return create_missing_fields_error();
    }

    let keypair = match validate_secret_key(&payload.secret) {
        Ok(kp) => kp,
        Err(_) => return create_error_response(),
    };

    let signature = keypair.sign_message(payload.message.as_bytes());
    let signature_b64 = general_purpose::STANDARD.encode(signature.as_ref());

    let response = SignMessageResponse {
        success: true,
        data: SignMessageResponseData {
            signature: signature_b64,
            public_key: bs58::encode(keypair.pubkey().to_bytes()).into_string(),
            message: payload.message,
        },
    };

    Json(response).into_response()
}

#[handler]
async fn verify_message(Json(payload): Json<VerifyMessageRequest>) -> Response {
    // Enhanced validation
    if validate_message(&payload.message).is_err()
        || payload.signature.trim().is_empty()
        || payload.pubkey.trim().is_empty()
    {
        return create_missing_fields_error();
    }

    let pubkey = match validate_pubkey(&payload.pubkey) {
        Ok(pk) => pk,
        Err(_) => return create_error_response(),
    };

    let signature = match validate_signature(&payload.signature) {
        Ok(sig) => sig,
        Err(_) => return create_error_response(),
    };

    let valid = signature.verify(pubkey.as_ref(), payload.message.as_bytes());

    let response = VerifyMessageResponse {
        success: true,
        data: VerifyMessageResponseData {
            valid,
            message: payload.message,
            pubkey: bs58::encode(pubkey.to_bytes()).into_string(),
        },
    };

    Json(response).into_response()
}

#[handler]
async fn send_sol(Json(payload): Json<SendSolRequest>) -> Response {
    // Validate inputs
    if payload.from.trim().is_empty() || payload.to.trim().is_empty() {
        return create_missing_fields_error();
    }

    if validate_amount(payload.lamports).is_err() {
        return create_error_response();
    }

    let from_pubkey = match validate_pubkey(&payload.from) {
        Ok(pk) => pk,
        Err(_) => return create_error_response(),
    };

    let to_pubkey = match validate_pubkey(&payload.to) {
        Ok(pk) => pk,
        Err(_) => return create_error_response(),
    };

    // Check if from and to are the same (edge case)
    if from_pubkey == to_pubkey {
        return create_error_response();
    }

    let ix = system_instruction::transfer(&from_pubkey, &to_pubkey, payload.lamports);
    let instruction_data = general_purpose::STANDARD.encode(&ix.data);

    let response = SendSolResponse {
        success: true,
        data: SolInstructionData {
            program_id: ix.program_id.to_string(),
            accounts: vec![from_pubkey.to_string(), to_pubkey.to_string()],
            instruction_data,
        },
    };

    Json(response).into_response()
}

#[handler]
async fn send_token(Json(payload): Json<SendTokenRequest>) -> Response {
    // Validate inputs
    if payload.destination.trim().is_empty()
        || payload.mint.trim().is_empty()
        || payload.owner.trim().is_empty()
    {
        return create_missing_fields_error();
    }

    if validate_amount(payload.amount).is_err() {
        return create_error_response();
    }

    let destination_pubkey = match validate_pubkey(&payload.destination) {
        Ok(pk) => pk,
        Err(_) => return create_error_response(),
    };

    let mint_pubkey = match validate_pubkey(&payload.mint) {
        Ok(pk) => pk,
        Err(_) => return create_error_response(),
    };

    let owner_pubkey = match validate_pubkey(&payload.owner) {
        Ok(pk) => pk,
        Err(_) => return create_error_response(),
    };

    let source_pubkey = get_associated_token_address(&owner_pubkey, &mint_pubkey);

    // Check if source and destination are the same (edge case)
    if source_pubkey == destination_pubkey {
        return create_error_response();
    }

    let ix = match transfer(
        &spl_token::id(),
        &source_pubkey,
        &destination_pubkey,
        &owner_pubkey,
        &[&owner_pubkey],
        payload.amount,
    ) {
        Ok(ix) => ix,
        Err(_) => return create_error_response(),
    };

    let instruction_data = general_purpose::STANDARD.encode(&ix.data);
    let accounts = ix
        .accounts
        .into_iter()
        .map(|meta| TokenAccountMeta {
            pubkey: meta.pubkey.to_string(),
            is_signer: meta.is_signer,
        })
        .collect();

    let response = SendTokenResponse {
        success: true,
        data: TokenTransferInstructionData {
            program_id: ix.program_id.to_string(),
            accounts,
            instruction_data,
        },
    };

    Json(response).into_response()
}

#[handler]
fn generate_keypair() -> Json<GenerateKeyPairOutput> {
    let keypair = Keypair::new();
    let response = GenerateKeyPairOutput {
        success: true,
        data: KeyPairData {
            pubkey: bs58::encode(keypair.pubkey().to_bytes()).into_string(),
            secret: bs58::encode(keypair.secret_bytes()).into_string(),
        },
    };
    Json(response)
}

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    let app = Route::new()
        .at("/keypair", post(generate_keypair))
        .at("/token/create", post(create_token))
        .at("/token/mint", post(mint_token))
        .at("/message/sign", post(sign_message))
        .at("/message/verify", post(verify_message))
        .at("/send/sol", post(send_sol))
        .at("/send/token", post(send_token));

    Server::new(TcpListener::bind("0.0.0.0:3000"))
        .run(app)
        .await
}
