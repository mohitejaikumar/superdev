use base64::{Engine as _, engine::general_purpose};
use bs58;
use poem::{
    EndpointExt, IntoResponse, Response, Result, Route, Server, handler, http::StatusCode,
    listener::TcpListener, middleware::Tracing, post, web::Json,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signature},
    signer::Signer,
    system_instruction,
};
use spl_associated_token_account::get_associated_token_address;
use spl_token::instruction::{initialize_mint, mint_to, transfer};

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
const MAX_LAMPORTS: u64 = u64::MAX / 2; // Prevent potential overflow

// Helper function to validate string length
fn validate_string_length(s: &str, max_len: usize) -> bool {
    s.len() <= max_len
}

// Helper function to safely extract string from JSON value
fn extract_string_from_json(value: &Value, key: &str) -> Option<String> {
    match value.get(key) {
        Some(Value::String(s)) => {
            if s.trim().is_empty() {
                None
            } else {
                Some(s.clone())
            }
        }
        _ => None,
    }
}

// Helper function to safely extract u64 from JSON value
fn extract_u64_from_json(value: &Value, key: &str) -> Option<u64> {
    match value.get(key) {
        Some(Value::Number(n)) => n.as_u64(),
        _ => None,
    }
}

// Helper function to safely extract u8 from JSON value
fn extract_u8_from_json(value: &Value, key: &str) -> Option<u8> {
    match value.get(key) {
        Some(Value::Number(n)) => {
            if let Some(val) = n.as_u64() {
                if val <= 255 { Some(val as u8) } else { None }
            } else {
                None
            }
        }
        _ => None,
    }
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

// Safe JSON parsing wrapper
fn parse_json_safely(body: String) -> Result<Value, Response> {
    // Handle empty body
    if body.trim().is_empty() {
        return Err(create_missing_fields_error());
    }

    // Try to parse JSON
    match serde_json::from_str::<Value>(&body) {
        Ok(value) => {
            // Check if it's an object
            if !value.is_object() {
                return Err(create_error_response());
            }
            Ok(value)
        }
        Err(_) => Err(create_error_response()),
    }
}

#[handler]
async fn create_token_safe(body: String) -> Response {
    let json_value = match parse_json_safely(body) {
        Ok(value) => value,
        Err(response) => return response,
    };

    // Extract fields safely
    let mint_authority = extract_string_from_json(&json_value, "mintAuthority");
    let mint = extract_string_from_json(&json_value, "mint");
    let decimals = extract_u8_from_json(&json_value, "decimals");

    // Check for missing required fields
    if mint_authority.is_none() || mint.is_none() || decimals.is_none() {
        return create_missing_fields_error();
    }

    let mint_authority_str = mint_authority.unwrap();
    let mint_str = mint.unwrap();
    let decimals_val = decimals.unwrap();

    // Enhanced validation
    if validate_decimals(decimals_val).is_err() {
        return create_error_response();
    }

    let mint_pubkey = match validate_pubkey(&mint_str) {
        Ok(pubkey) => pubkey,
        Err(_) => return create_error_response(),
    };

    let mint_authority = match validate_pubkey(&mint_authority_str) {
        Ok(pubkey) => pubkey,
        Err(_) => return create_error_response(),
    };

    let ix = match initialize_mint(
        &spl_token::id(),
        &mint_pubkey,
        &mint_authority,
        None,
        decimals_val,
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
async fn mint_token_safe(body: String) -> Response {
    let json_value = match parse_json_safely(body) {
        Ok(value) => value,
        Err(response) => return response,
    };

    // Extract fields safely
    let mint = extract_string_from_json(&json_value, "mint");
    let destination = extract_string_from_json(&json_value, "destination");
    let authority = extract_string_from_json(&json_value, "authority");
    let amount = extract_u64_from_json(&json_value, "amount");

    // Check for missing required fields
    if mint.is_none() || destination.is_none() || authority.is_none() || amount.is_none() {
        return create_missing_fields_error();
    }

    let mint_str = mint.unwrap();
    let destination_str = destination.unwrap();
    let authority_str = authority.unwrap();
    let amount_val = amount.unwrap();

    // Enhanced validation
    if validate_amount(amount_val).is_err() {
        return create_error_response();
    }

    let mint_pubkey = match validate_pubkey(&mint_str) {
        Ok(pubkey) => pubkey,
        Err(_) => return create_error_response(),
    };

    let destination_pubkey = match validate_pubkey(&destination_str) {
        Ok(pubkey) => pubkey,
        Err(_) => return create_error_response(),
    };

    let authority_pubkey = match validate_pubkey(&authority_str) {
        Ok(pubkey) => pubkey,
        Err(_) => return create_error_response(),
    };

    let ix = match mint_to(
        &spl_token::id(),
        &mint_pubkey,
        &destination_pubkey,
        &authority_pubkey,
        &[&authority_pubkey],
        amount_val,
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
async fn sign_message_safe(body: String) -> Response {
    let json_value = match parse_json_safely(body) {
        Ok(value) => value,
        Err(response) => return response,
    };

    // Extract fields safely
    let message = extract_string_from_json(&json_value, "message");
    let secret = extract_string_from_json(&json_value, "secret");

    // Check for missing required fields
    if message.is_none() || secret.is_none() {
        return create_missing_fields_error();
    }

    let message_str = message.unwrap();
    let secret_str = secret.unwrap();

    // Enhanced validation
    if validate_message(&message_str).is_err() {
        return create_missing_fields_error();
    }

    let keypair = match validate_secret_key(&secret_str) {
        Ok(kp) => kp,
        Err(_) => return create_error_response(),
    };

    let signature = keypair.sign_message(message_str.as_bytes());
    let signature_b64 = general_purpose::STANDARD.encode(signature.as_ref());

    let response = SignMessageResponse {
        success: true,
        data: SignMessageResponseData {
            signature: signature_b64,
            public_key: bs58::encode(keypair.pubkey().to_bytes()).into_string(),
            message: message_str,
        },
    };

    Json(response).into_response()
}

#[handler]
async fn verify_message_safe(body: String) -> Response {
    let json_value = match parse_json_safely(body) {
        Ok(value) => value,
        Err(response) => return response,
    };

    // Extract fields safely
    let message = extract_string_from_json(&json_value, "message");
    let signature = extract_string_from_json(&json_value, "signature");
    let pubkey = extract_string_from_json(&json_value, "pubkey");

    // Check for missing required fields
    if message.is_none() || signature.is_none() || pubkey.is_none() {
        return create_missing_fields_error();
    }

    let message_str = message.unwrap();
    let signature_str = signature.unwrap();
    let pubkey_str = pubkey.unwrap();

    // Enhanced validation
    if validate_message(&message_str).is_err() {
        return create_missing_fields_error();
    }

    let pubkey = match validate_pubkey(&pubkey_str) {
        Ok(pk) => pk,
        Err(_) => return create_error_response(),
    };

    let signature = match validate_signature(&signature_str) {
        Ok(sig) => sig,
        Err(_) => return create_error_response(),
    };

    let valid = signature.verify(pubkey.as_ref(), message_str.as_bytes());

    let response = VerifyMessageResponse {
        success: true,
        data: VerifyMessageResponseData {
            valid,
            message: message_str,
            pubkey: bs58::encode(pubkey.to_bytes()).into_string(),
        },
    };

    Json(response).into_response()
}

#[handler]
async fn send_sol_safe(body: String) -> Response {
    let json_value = match parse_json_safely(body) {
        Ok(value) => value,
        Err(response) => return response,
    };

    // Extract fields safely
    let from = extract_string_from_json(&json_value, "from");
    let to = extract_string_from_json(&json_value, "to");
    let lamports = extract_u64_from_json(&json_value, "lamports");

    // Check for missing required fields
    if from.is_none() || to.is_none() || lamports.is_none() {
        return create_missing_fields_error();
    }

    let from_str = from.unwrap();
    let to_str = to.unwrap();
    let lamports_val = lamports.unwrap();

    if validate_amount(lamports_val).is_err() {
        return create_error_response();
    }

    let from_pubkey = match validate_pubkey(&from_str) {
        Ok(pk) => pk,
        Err(_) => return create_error_response(),
    };

    let to_pubkey = match validate_pubkey(&to_str) {
        Ok(pk) => pk,
        Err(_) => return create_error_response(),
    };

    // Check if from and to are the same (edge case)
    if from_pubkey == to_pubkey {
        return create_error_response();
    }

    let ix = system_instruction::transfer(&from_pubkey, &to_pubkey, lamports_val);
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
async fn send_token_safe(body: String) -> Response {
    let json_value = match parse_json_safely(body) {
        Ok(value) => value,
        Err(response) => return response,
    };

    // Extract fields safely
    let destination = extract_string_from_json(&json_value, "destination");
    let mint = extract_string_from_json(&json_value, "mint");
    let owner = extract_string_from_json(&json_value, "owner");
    let amount = extract_u64_from_json(&json_value, "amount");

    // Check for missing required fields
    if destination.is_none() || mint.is_none() || owner.is_none() || amount.is_none() {
        return create_missing_fields_error();
    }

    let destination_str = destination.unwrap();
    let mint_str = mint.unwrap();
    let owner_str = owner.unwrap();
    let amount_val = amount.unwrap();

    if validate_amount(amount_val).is_err() {
        return create_error_response();
    }

    let destination_pubkey = match validate_pubkey(&destination_str) {
        Ok(pk) => pk,
        Err(_) => return create_error_response(),
    };

    let mint_pubkey = match validate_pubkey(&mint_str) {
        Ok(pk) => pk,
        Err(_) => return create_error_response(),
    };

    let owner_pubkey = match validate_pubkey(&owner_str) {
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
        amount_val,
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
        .at("/token/create", post(create_token_safe))
        .at("/token/mint", post(mint_token_safe))
        .at("/message/sign", post(sign_message_safe))
        .at("/message/verify", post(verify_message_safe))
        .at("/send/sol", post(send_sol_safe))
        .at("/send/token", post(send_token_safe))
        .with(Tracing);

    Server::new(TcpListener::bind("0.0.0.0:3000"))
        .run(app)
        .await
}
