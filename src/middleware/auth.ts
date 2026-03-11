import { Request, Response, NextFunction } from 'express';

export function requireApiSecret(req: Request, res: Response, next: NextFunction): void {
  const secret = req.headers['x-api-secret'] ?? req.headers['authorization']?.replace('Bearer ', '');

  if (!secret || secret !== process.env.API_SECRET) {
    res.status(401).json({ error: 'Unauthorized' });
    return;
  }

  next();
}
