import fs from 'fs';
import path from 'path';
import zlib from 'zlib';

const VPS_AGENT_DIR_CANDIDATES = [
  path.resolve(process.cwd(), 'vps-agent'),
  path.resolve(__dirname, '../../vps-agent'),
];

function readVpsAgentAsset(filename: string): string {
  for (const dir of VPS_AGENT_DIR_CANDIDATES) {
    const fullPath = path.join(dir, filename);
    if (fs.existsSync(fullPath)) {
      return fs.readFileSync(fullPath, 'utf8').trim();
    }
  }

  throw new Error(`Missing VPS agent asset: ${filename}`);
}

function gzipBase64(content: string): string {
  return zlib.gzipSync(Buffer.from(content, 'utf8')).toString('base64');
}

export const VPS_AGENT_PACKAGE_JSON = readVpsAgentAsset('package.json');
export const VPS_AGENT_SERVER_JS = readVpsAgentAsset('server.js');
export const VPS_AGENT_PACKAGE_JSON_GZIP_B64 = gzipBase64(VPS_AGENT_PACKAGE_JSON);
export const VPS_AGENT_SERVER_JS_GZIP_B64 = gzipBase64(VPS_AGENT_SERVER_JS);
