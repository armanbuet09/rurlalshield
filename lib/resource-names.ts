import { createHash } from 'crypto';

/** Keep readable physical names within AWS limits without colliding after truncation. */
export function boundedResourceName(name: string, maxLength: number): string {
  if (name.length <= maxLength) return name;
  const suffix = createHash('sha256').update(name).digest('hex').slice(0, 8);
  return `${name.slice(0, maxLength - suffix.length - 1)}-${suffix}`;
}
