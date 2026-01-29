/**
 * Estrutura de dados retornada pelo método encrypt()
 * Contém todos os metadados necessários para descriptografia
 */
export interface EncryptedData {
  /** Salt usado para derivar a chave da Camada 1 (AES-256-GCM) */
  salt1: string;
  
  /** Salt usado para derivar a chave da Camada 2 (ChaCha20-Poly1305) */
  salt2: string;
  
  /** Initialization Vector (IV) da Camada 1 - 12 bytes para GCM */
  iv1: string;
  
  /** Initialization Vector (IV) da Camada 2 - 12 bytes para Poly1305 */
  iv2: string;
  
  /** Authentication Tag da Camada 1 (AES-256-GCM) - 16 bytes */
  authTag1: string;
  
  /** Authentication Tag da Camada 2 (ChaCha20-Poly1305) - 16 bytes */
  authTag2: string;
  
  /** Dados criptografados finais (após ambas as camadas) em base64 */
  ciphertext: string;
}

/**
 * Estrutura de dados extraída de um buffer binário customizado (.dy)
 * Agora inclui TODOS os metadados necessários em um único arquivo
 */
export interface UnpackedData {
  /** Salt 1 para derivar chave da Camada 1 */
  salt1: Buffer;
  
  /** Salt 2 para derivar chave da Camada 2 */
  salt2: Buffer;
  
  /** IV da Camada 1 */
  iv1: Buffer;
  
  /** IV da Camada 2 */
  iv2: Buffer;
  
  /** Authentication Tag da Camada 1 */
  authTag1: Buffer;
  
  /** Authentication Tag da Camada 2 */
  authTag2: Buffer;
  
  /** Payload criptografado */
  encryptedData: Buffer;
}
