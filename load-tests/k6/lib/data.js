export function deterministicUUID(index) {
  const value = Math.abs(Number(index)).toString(16).padStart(12, '0').slice(-12);
  return `00000000-0000-4000-8000-${value}`;
}

export function pick(values, iteration = __ITER) { return values[iteration % values.length]; }
