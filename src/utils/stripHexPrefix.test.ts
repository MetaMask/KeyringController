import stripHexPrefix from './stripHexPrefix';

describe('stripHexPrefix', () => {
  it('should return the value without the hex prefix', () => {
    const hexWithPrefix = '0x123';
    const expectedResult = '123';
    expect(stripHexPrefix(hexWithPrefix)).toBe(expectedResult);
  });
});
