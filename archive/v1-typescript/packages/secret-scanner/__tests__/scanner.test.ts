import { describe, it, expect } from 'vitest';
import { scan } from '../src/scanner.js';

describe('secret-scanner', () => {
  it('passes a clean file', () => {
    expect(scan('const x = 1;\nconsole.log("hello world");')).toEqual([]);
  });

  it('detects cn- prefixed key', () => {
    const findings = scan('const apiKey = "cn-abcdefghijklmnopqrstuvwxyz0123456"'); // noscan
    expect(findings).toHaveLength(1);
    expect(findings[0].pattern).toContain('cn-');
    expect(findings[0].line).toBe(1);
  });

  it('detects BEGIN PRIVATE KEY', () => {
    const header = '-----BEGIN PRIVATE KEY-----'; // noscan
    const content = `${header}\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEA\n-----END PRIVATE KEY-----`;
    const findings = scan(content);
    expect(findings).toHaveLength(1);
    expect(findings[0].pattern).toContain('Private key');
  });

  it('detects BEGIN RSA PRIVATE KEY', () => {
    const findings = scan('-----BEGIN RSA PRIVATE KEY-----'); // noscan
    expect(findings).toHaveLength(1);
  });

  it('detects BEGIN OPENSSH PRIVATE KEY', () => {
    const findings = scan('-----BEGIN OPENSSH PRIVATE KEY-----'); // noscan
    expect(findings).toHaveLength(1);
  });

  it('detects sk- key', () => {
    const findings = scan('const secret = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789"'); // noscan
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].pattern).toContain('sk-');
  });

  it('detects Anthropic key', () => {
    const findings = scan('const key = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789012345678901234"'); // noscan
    expect(findings.length).toBeGreaterThan(0);
  });

  it('detects AWS access key', () => {
    const findings = scan('AWS_KEY=AKIAIOSFODNN7EXAMPLE'); // noscan
    expect(findings.length).toBeGreaterThan(0);
  });

  it('detects secret env var with long base64 value', () => {
    const findings = scan('DATABASE_SECRET_KEY=YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkwYWJjZGVm'); // noscan
    expect(findings.length).toBeGreaterThan(0);
  });

  it('does not flag short sk- strings', () => {
    expect(scan('const key = "sk-short"')).toEqual([]);
  });

  it('does not flag cn- without enough chars', () => {
    expect(scan('prefix cn-tiny suffix')).toEqual([]);
  });

  it('reports correct line numbers', () => {
    const content = 'line one\nline two\nconst k = "sk-abcdefghijklmnopqrstuvwxyz123456"\nline four'; // noscan
    const findings = scan(content);
    expect(findings[0].line).toBe(3);
  });

  it('noscan suppression skips the line', () => {
    expect(scan('const k = "sk-realkey-abcdefghijklmnop" // noscan')).toEqual([]);
  });
});
