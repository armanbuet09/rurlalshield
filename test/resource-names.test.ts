import { boundedResourceName } from '../lib/resource-names';

describe('AWS resource name limits', () => {
  test('preserves names already within the limit', () => {
    expect(boundedResourceName('clinic-rural-shield-api', 50)).toBe('clinic-rural-shield-api');
  });

  test('long names remain stable, valid, and distinct when only their tails differ', () => {
    const prefix = `${'a'.repeat(24)}-rural-shield-${'b'.repeat(30)}`;
    const primary = boundedResourceName(`${prefix}c`, 50);
    const otherWorkload = boundedResourceName(`${prefix}d`, 50);
    const dr = boundedResourceName(`${prefix}c-dr`, 50);
    for (const name of [primary, otherWorkload, dr]) {
      expect(name).toMatch(/^[a-zA-Z0-9_-]{2,50}$/);
    }
    expect(new Set([primary, otherWorkload, dr]).size).toBe(3);
    expect(boundedResourceName(`${prefix}c`, 50)).toBe(primary);
  });
});
