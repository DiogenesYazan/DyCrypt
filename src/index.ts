/**
 * DyCrypt - Biblioteca de Criptografia em Cascata de Alta Segurança
 * 
 * Exports principais:
 * - DyCrypt: Classe principal com métodos encrypt() e decrypt()
 * - packData: Converte componentes para formato binário .secreto
 * - unpackData: Extrai componentes de formato binário .secreto
 * - EncryptedData: Tipo TypeScript da estrutura retornada por encrypt()
 * - UnpackedData: Tipo TypeScript da estrutura retornada por unpackData()
 */

export { DyCrypt } from './DyCrypt.js';
export { packData } from './utils/packData.js';
export { unpackData } from './utils/unpackData.js';
export type { EncryptedData, UnpackedData } from './types.js';
