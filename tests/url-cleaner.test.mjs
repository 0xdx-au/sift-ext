import test from 'node:test';
import assert from 'node:assert/strict';
import { cleanTrackingUrl } from '../src/url-cleaner.mjs';
test('removes only exact known parameters without reserialising other bytes', () => {
  assert.deepEqual(cleanTrackingUrl('https://example.org/?q=a%2Bb&utm_source=one&gclid=123#frag'), {
    changed:true,value:'https://example.org/?q=a%2Bb#frag',removed:2
  });
});
test('leaves OAuth, signed, invite and payment flows untouched', () => {
  for (const url of [
    'https://example.org/oauth/callback?code=abc&utm_source=test',
    'https://example.org/file?X-Amz-Signature=a&utm_medium=x',
    'https://example.org/checkout?utm_campaign=x',
    'https://example.org/?state=a&fbclid=b',
    'https://example.org/share?fbclid=x'
  ]) assert.equal(cleanTrackingUrl(url).changed,false,url);
});
test('preserves query duplicates, case-sensitive application values and fragments', () => {
  assert.equal(cleanTrackingUrl('https://example.org/?a=1&a=2&UTM_MEDIUM=c#top').value,
    'https://example.org/?a=1&a=2#top');
  assert.equal(cleanTrackingUrl('https://example.org/?ref=keep').changed,false);
  assert.equal(cleanTrackingUrl('https://example.org/?bad=%zz&utm_source=x').changed,false);
  assert.equal(cleanTrackingUrl('https://example.org/#fragment?utm_source=x').changed,false);
});
test('rejects non-web schemes, malformed URLs and credentials', () => {
  for (const url of ['javascript:alert(1)','garbage','https://user:pass@example.org/?utm_source=x']) {
    assert.equal(cleanTrackingUrl(url).changed,false);
  }
});

test('refuses encoded paths which may hide login, callback or signed routes', () => {
  for (const url of [
    'https://example.org/oauth%2Fcallback?utm_source=x',
    'https://example.org/%6cogin?utm_medium=x',
    'https://example.org/auth%252Fcallback?gclid=x',
    'https://example.org/files/%2fsecret?utm_campaign=x',
    'https://example.org/%zz?fbclid=x'
  ]) {
    const result = cleanTrackingUrl(url);
    assert.equal(result.changed, false, url);
  }
});
