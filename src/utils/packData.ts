/**
 * Empacota dados criptografados em um formato binário customizado
 * 
 * Estrutura do Buffer (.dy) - VERSÃO MELHORADA:
 * ===============================================
 * [  0-15 bytes] Salt 1 (128 bits)
 * [ 16-31 bytes] Salt 2 (128 bits)
 * [ 32-43 bytes] IV Camada 1 (96 bits)
 * [ 44-55 bytes] IV Camada 2 (96 bits)
 * [ 56-71 bytes] Auth Tag 1 (128 bits)
 * [ 72-87 bytes] Auth Tag 2 (128 bits)
 * [88-N  bytes] Payload criptografado (tamanho variável)
 * 
 * Por que incluir tudo?
 * --------------------
 * 1. Arquivo único - sem risco de perder metadados
 * 2. Integridade garantida - auth tags junto com dados
 * 3. Mais fácil de gerenciar
 * 4. Padrão da indústria (ex: age encryption)
 * 
 * Nota de Segurança:
 * ------------------
 * IVs, salts e auth tags NÃO são secretos. A segurança depende da senha mestra.
 * 
 * @param salt1 Salt da Camada 1 (deve ter 16 bytes)
 * @param salt2 Salt da Camada 2 (deve ter 16 bytes)
 * @param iv1 IV da Camada 1 - AES-256-GCM (deve ter 12 bytes)
 * @param iv2 IV da Camada 2 - ChaCha20-Poly1305 (deve ter 12 bytes)
 * @param authTag1 Auth Tag da Camada 1 (deve ter 16 bytes)
 * @param authTag2 Auth Tag da Camada 2 (deve ter 16 bytes)
 * @param encryptedData Payload criptografado (tamanho variável)
 * @returns Buffer único contendo todos os dados concatenados
 * @throws Error se os tamanhos dos parâmetros não estiverem corretos
 */
export function packData(
  salt1: Buffer,
  salt2: Buffer,
  iv1: Buffer,
  iv2: Buffer,
  authTag1: Buffer,
  authTag2: Buffer,
  encryptedData: Buffer
): Buffer {
  // valida tamanhos
  if (salt1.length !== 16) {
    throw new Error(`Salt1 deve ter exatamente 16 bytes (recebido: ${salt1.length})`);
  }
  if (salt2.length !== 16) {
    throw new Error(`Salt2 deve ter exatamente 16 bytes (recebido: ${salt2.length})`);
  }
  if (iv1.length !== 12) {
    throw new Error(`IV1 deve ter exatamente 12 bytes (recebido: ${iv1.length})`);
  }
  if (iv2.length !== 12) {
    throw new Error(`IV2 deve ter exatamente 12 bytes (recebido: ${iv2.length})`);
  }
  if (authTag1.length !== 16) {
    throw new Error(`AuthTag1 deve ter exatamente 16 bytes (recebido: ${authTag1.length})`);
  }
  if (authTag2.length !== 16) {
    throw new Error(`AuthTag2 deve ter exatamente 16 bytes (recebido: ${authTag2.length})`);
  }

  // calcula tamanho total: 88 bytes header + payload
  const totalSize = 88 + encryptedData.length;
  
  // aloca buffer
  const packed = Buffer.allocUnsafe(totalSize);
  
  // escreve header de 88 bytes
  let offset = 0;
  
  salt1.copy(packed, offset);
  offset += 16;
  
  salt2.copy(packed, offset);
  offset += 16;
  
  iv1.copy(packed, offset);
  offset += 12;
  
  iv2.copy(packed, offset);
  offset += 12;
  
  authTag1.copy(packed, offset);
  offset += 16;
  
  authTag2.copy(packed, offset);
  offset += 16;
  
  // escreve payload
  encryptedData.copy(packed, offset);
  
  return packed;
}
