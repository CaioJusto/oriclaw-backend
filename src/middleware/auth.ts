import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';

export function requireApiSecret(req: Request, res: Response, next: NextFunction): void {
  const secret = req.headers['x-api-secret'] ?? req.headers['authorization']?.replace('Bearer ', '');
  const expected = process.env.API_SECRET;

  if (!secret || !expected || typeof secret !== 'string') {
    res.status(401).json({ error: 'Unauthorized' });
    return;
  }

  const secretBuf = Buffer.from(secret);
  const expectedBuf = Buffer.from(expected);
  if (secretBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(secretBuf, expectedBuf)) {
    res.status(401).json({ error: 'Unauthorized' });
    return;
  }

  next();
}
