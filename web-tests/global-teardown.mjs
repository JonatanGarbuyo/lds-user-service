import { execFileSync } from 'node:child_process';

export default async function globalTeardown() {
  try {
    const ids = execFileSync('docker', ['ps', '-q', '--filter', 'label=lds-user-service-browser-api'], {
      encoding: 'utf8'
    }).trim();
    if (ids) {
      execFileSync('docker', ['stop', ...ids.split('\n')], { stdio: 'ignore' });
    }
  } catch {
    // Docker is not used when Go is available or Docker is not installed.
  }
}
