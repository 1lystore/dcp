import { describe, it, expect } from 'vitest';
import { execSync } from 'child_process';
import * as path from 'path';

describe('dcp-proxy', () => {
  it('shows help output', () => {
    const cliPath = path.join(__dirname, '..', 'dist', 'index.js');
    const output = execSync(`node ${cliPath} --help`, {
      encoding: 'utf8',
      timeout: 30000,
    });

    expect(output).toContain('Run a local DCP proxy for remote agents');
    expect(output).toContain('--pair');
    expect(output).toContain('--hpke-key');
  });
});
