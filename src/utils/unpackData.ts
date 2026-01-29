import type { UnpackedData } from '../types.js';

/**
 * Desempacota um buffer binário customizado para extrair componentes individuais
 * 
 * Formato Esperado (.dy) - VERSÃO MELHORADA:
 * ===========================================
 * [  0-15 bytes] Salt 1 (128 bits)
 * [ 16-31 bytes] Salt 2 (128 bits)
 * [ 32-43 bytes] IV Camada 1 (96 bits)
 * [ 44-55 bytes] IV Camada 2 (96 bits)
 * [ 56-71 bytes] Auth Tag 1 (128 bits)
 * [ 72-87 bytes] Auth Tag 2 (128 bits)
 * [88-N  bytes] Payload criptografado (tamanho variável)
 * 
 * Segurança:
 * ----------
 * Esta função NÃO valida a integridade criptográfica dos dados.
 * A validação ocorre durante a descriptografia pelos auth tags.
 * 
 * @param buffer Buffer binário empacotado pelo packData()
 * @returns Objeto com todos os componentes extraídos
 * @throws Error se o buffer for muito pequeno (< 88 bytes)
 */
export function unpackData(buffer: Buffer): UnpackedData {
  // header agora tem 88 bytes (antes era 40)
  const HEADER_SIZE = 88;
  
  if (buffer.length < HEADER_SIZE) {
    throw new Error(
      `Arquivo corrompido: tamanho mínimo ${HEADER_SIZE} bytes (recebido: ${buffer.length})`
    );
  }

  let offset = 0;
  
  // extrai todos os metadados
  const salt1 = buffer.subarray(offset, offset + 16);
  offset += 16;
  
  const salt2 = buffer.subarray(offset, offset + 16);
  offset += 16;
  
  const iv1 = buffer.subarray(offset, offset + 12);
  offset += 12;
  
  const iv2 = buffer.subarray(offset, offset + 12);
  offset += 12;
  
  const authTag1 = buffer.subarray(offset, offset + 16);
  offset += 16;
  
  const authTag2 = buffer.subarray(offset, offset + 16);
  offset += 16;
  
  // restante é o payload criptografado
  const encryptedData = buffer.subarray(offset);

  return {
    salt1,
    salt2,
    iv1,
    iv2,
    authTag1,
    authTag2,
    encryptedData
  };
}
