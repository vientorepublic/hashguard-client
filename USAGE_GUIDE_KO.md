# HashGuard Client SDK 실전 가이드

## 🎯 초급: 기본 사용법

### 1단계: 설치

```bash
npm install @hashguard/client
```

### 2단계: 클라이언트 초기화

```typescript
import { HashGuardClient } from '@hashguard/client';

const client = new HashGuardClient({
  baseUrl: 'https://pow.example.com', // HashGuard 서버 주소
});
```

### 3단계: 완전한 흐름 실행

```typescript
try {
  // 단 3줄로 challenge → solve → verify 완료!
  const result = await client.execute('login');

  // 백엔드로 토큰 전송
  const response = await fetch('/api/login', {
    method: 'POST',
    headers: {
      'X-Proof-Token': result.verification.proofToken,
    },
    body: JSON.stringify({ username: 'user' }),
  });
} catch (error) {
  console.error('PoW failed:', error.message);
}
```

---

## 🔧 중급: 상세 제어

### 분리된 단계별 실행

각 단계를 개별적으로 제어할 수 있습니다:

```typescript
import { HashGuardClient, solvePow } from '@hashguard/client';

const client = new HashGuardClient({
  baseUrl: 'https://pow.example.com',
  timeout: 15_000,
});

// 1️⃣ Challenge 발급
const challenge = await client.issueChallenge('login');
console.log(`Difficulty: ${challenge.difficultyBits} bits`);
console.log(`Expires: ${challenge.expiresAt}`);

// 2️⃣ 로컬에서 PoW 계산 (UI 피드백 가능)
const solveResult = solvePow(challenge.challengeId, challenge.seed, challenge.target, {
  maxAttempts: 50_000_000,
  timeoutMs: 120_000,
  progressInterval: 500_000,
  onProgress: (attempts) => {
    console.log(`Attempted ${attempts} nonces...`);
    updateProgressBar((attempts / 50_000_000) * 100);
  },
});

console.log(`Found nonce after ${solveResult.attempts} attempts`);
console.log(`Time spent: ${solveResult.solveTimeMs}ms`);

// 3️⃣ 검증 및 토큰 획득
const verification = await client.verifyChallenge(
  challenge.challengeId,
  solveResult.nonce,
  solveResult.solveTimeMs
);

console.log('Token acquired:', verification.proofToken);
```

### 에러 처리

```typescript
import { HashGuardClient, SolverTimeoutError, HashGuardError } from '@hashguard/client';

const client = new HashGuardClient({
  baseUrl: 'https://pow.example.com',
});

try {
  const result = await client.execute('login');
} catch (error) {
  if (error instanceof SolverTimeoutError) {
    // PoW 계산이 시간 초과
    console.error(
      `Solver gave up after ${error.attempts} attempts (${error.elapsedMs}ms)`
    );
    // UI에 "계산 시간이 너무 오래 걸렸습니다" 메시지 표시
  } else if (error instanceof HashGuardError) {
    // 서버 오류
    if (error.code === 'POW_CHALLENGE_NOT_FOUND') {
      console.error('Challenge expired or already used');
    } else if (error.code === 'POW_INVALID_PROOF') {
      console.error('Nonce does not satisfy target (solver bug?)');
    } else {
      console.error(`Server error [${error.code}]:`, error.message);
    }
  } else {
    // 예상치 못한 오류
    console.error('Unexpected error:', error);
  }
}
```

---

## 🌐 웹 브라우저 통합

### Express.js 백엔드 예제

```typescript
// server.ts
import express from 'express';
import { HashGuardClient } from '@hashguard/client';

const app = express();
const powClient = new HashGuardClient({
  baseUrl: 'https://pow.example.com',
});

// 보호된 엔드포인트
app.post('/api/login', async (req, res) => {
  const proofToken = req.headers['x-proof-token'] as string;

  if (!proofToken) {
    return res.status(400).json({ error: 'Missing proof token' });
  }

  try {
    // 토큰 검증
    const tokenInfo = await powClient.introspectToken(proofToken);

    // 토큰이 유효하고 소비됨 (일회용)
    const username = req.body.username;
    const clientIp = req.ip;

    // 토큰의 IP와 현재 요청 IP 비교 (선택사항)
    if (tokenInfo.subject !== clientIp) {
      return res.status(403).json({ error: 'IP mismatch' });
    }

    // ✓ 로그인 진행
    const user = await authenticateUser(username);
    res.json({ success: true, user });
  } catch (error) {
    if (error.code === 'POW_TOKEN_ALREADY_USED') {
      res.status(409).json({ error: 'Token already used (replay attack?)' });
    } else if (error.code === 'POW_TOKEN_EXPIRED') {
      res.status(401).json({ error: 'Token expired' });
    } else {
      res.status(401).json({ error: 'Invalid token' });
    }
  }
});

app.listen(3000);
```

### HTML/Vue.js 프론트엔드

```vue
<template>
  <div class="login-form">
    <input v-model="username" placeholder="Username" />

    <button @click="handleLogin" :disabled="isLoading">
      {{ isLoading ? `Computing PoW (${progress}%)...` : 'Login' }}
    </button>

    <div v-if="error" class="error">{{ error }}</div>
  </div>
</template>

<script setup>
import { ref } from 'vue';
import { HashGuardClient, SolverTimeoutError } from '@hashguard/client';

const username = ref('');
const isLoading = ref(false);
const error = ref('');
const progress = ref(0);

const client = new HashGuardClient({
  baseUrl: 'https://pow.example.com',
});

async function handleLogin() {
  if (!username.value) {
    error.value = 'Username required';
    return;
  }

  isLoading.value = true;
  error.value = '';
  progress.value = 0;

  try {
    // PoW 계산 (진행률 표시)
    const result = await client.execute('login', {
      timeoutMs: 120_000,
      onProgress: (attempts) => {
        progress.value = Math.min(100, Math.floor((attempts / 1_000_000) * 100));
      },
    });

    // 백엔드에 로그인 요청
    const response = await fetch('/api/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Proof-Token': result.verification.proofToken,
      },
      body: JSON.stringify({ username: username.value }),
    });

    if (response.ok) {
      const data = await response.json();
      console.log('Login successful:', data);
      // 리다이렉트 또는 앱 상태 업데이트
    } else {
      error.value = `Login failed: ${response.statusText}`;
    }
  } catch (err) {
    if (err instanceof SolverTimeoutError) {
      error.value = `PoW 계산이 너무 오래 걸렸습니다 (${err.attempts} attempts)`;
    } else {
      error.value = err.message || 'PoW verification failed';
    }
  } finally {
    isLoading.value = false;
  }
}
</script>

<style scoped>
.error {
  color: red;
  margin-top: 10px;
}
button:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}
</style>
```

### React 예제

```tsx
import { useState } from 'react';
import { HashGuardClient, SolverTimeoutError } from '@hashguard/client';

const client = new HashGuardClient({
  baseUrl: 'https://pow.example.com',
});

export function LoginForm() {
  const [username, setUsername] = useState('');
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState('');

  async function handleLogin(e: React.FormEvent) {
    e.preventDefault();
    if (!username) return;

    setLoading(true);
    setError('');
    setProgress(0);

    try {
      const result = await client.execute('login', {
        timeoutMs: 120_000,
        onProgress: (attempts) => {
          setProgress(Math.min(100, Math.floor((attempts / 1_000_000) * 100)));
        },
      });

      const response = await fetch('/api/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Proof-Token': result.verification.proofToken,
        },
        body: JSON.stringify({ username }),
      });

      if (response.ok) {
        // 로그인 성공
        const data = await response.json();
        localStorage.setItem('token', data.token);
        window.location.href = '/dashboard';
      } else {
        setError('Login failed');
      }
    } catch (err) {
      if (err instanceof SolverTimeoutError) {
        setError(`PoW solving timeout after ${err.attempts} attempts`);
      } else {
        setError((err as Error).message);
      }
    } finally {
      setLoading(false);
    }
  }

  return (
    <form onSubmit={handleLogin}>
      <input
        type="text"
        value={username}
        onChange={(e) => setUsername(e.target.value)}
        placeholder="Username"
        disabled={loading}
      />
      <button type="submit" disabled={loading}>
        {loading ? `Computing PoW... ${progress}%` : 'Login'}
      </button>
      {error && <p style={{ color: 'red' }}>{error}</p>}
    </form>
  );
}
```

---

## 🛡️ 고급: 재시도 로직 및 타임아웃

### 연속 실패 처리 (지수 백오프)

```typescript
import { HashGuardClient, SolverTimeoutError, HashGuardError } from '@hashguard/client';

async function executeWithBackoff(
  client: HashGuardClient,
  context: string,
  maxRetries = 3
) {
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      return await client.execute(context, {
        timeoutMs: 60_000 * (attempt + 1), // 시도마다 timeout 증가
      });
    } catch (error) {
      if (attempt === maxRetries - 1) {
        throw error; // 마지막 시도 실패
      }

      // 지수 백오프: 1초, 2초, 4초...
      const delayMs = Math.pow(2, attempt) * 1000;
      console.log(`Attempt ${attempt + 1} failed, retrying in ${delayMs}ms...`);
      await new Promise((r) => setTimeout(r, delayMs));
    }
  }
}

// 사용
try {
  const result = await executeWithBackoff(client, 'login');
} catch (error) {
  console.error('All retries exhausted:', error);
}
```

### 사용자 정의 solver options

```typescript
// 느린 기기를 위한 약한 설정
const slowDeviceOptions = {
  maxAttempts: 10_000_000, // 기본보다 적음
  timeoutMs: 300_000, // 5분 허용
  progressInterval: 500_000,
};

const result = await client.execute('login', slowDeviceOptions);

// 빠른 기기를 위한 강한 설정
const fastDeviceOptions = {
  maxAttempts: 100_000_000, // 더 많이 시도
  timeoutMs: 60_000, // 1분만
  progressInterval: 1_000_000,
};

const result = await client.execute('premium', fastDeviceOptions);
```

---

## 📊 모니터링 및 로깅

```typescript
import { HashGuardClient, SolverTimeoutError, HashGuardError } from '@hashguard/client';

class MonitoredHashGuardClient extends HashGuardClient {
  private metrics = {
    totalAttempts: 0,
    successCount: 0,
    timeoutCount: 0,
    serverErrorCount: 0,
  };

  async execute(context?: string, solverOptions?: any) {
    const startTime = performance.now();

    try {
      const result = await super.execute(context, solverOptions);
      this.metrics.successCount++;
      this.metrics.totalAttempts += result.solveResult.attempts;

      console.log({
        event: 'pow_success',
        context,
        attempts: result.solveResult.attempts,
        solveTimeMs: result.solveResult.solveTimeMs,
        elapsedMs: performance.now() - startTime,
      });

      return result;
    } catch (error) {
      if (error instanceof SolverTimeoutError) {
        this.metrics.timeoutCount++;
        console.error({
          event: 'pow_timeout',
          context,
          attempts: error.attempts,
          elapsedMs: error.elapsedMs,
        });
      } else if (error instanceof HashGuardError) {
        this.metrics.serverErrorCount++;
        console.error({
          event: 'pow_server_error',
          context,
          code: error.code,
          status: error.status,
        });
      }
      throw error;
    }
  }

  getMetrics() {
    return this.metrics;
  }
}

// 사용
const client = new MonitoredHashGuardClient({
  baseUrl: 'https://pow.example.com',
});

// 주기적으로 메트릭 수집
setInterval(() => {
  const metrics = client.getMetrics();
  console.log('PoW Metrics:', metrics);
  // 분석 서비스로 전송
}, 60000);
```

---

## 🔒 보안 모범 사례

### 1. 토큰 검증 (백엔드)

```typescript
// ❌ 나쁜 예: 클라이언트 토큰을 신뢰
if (req.headers['x-proof-token']) {
  // 자동 허용 → 보안 허점!
}

// ✅ 좋은 예: 항상 서버에서 검증
const tokenInfo = await powClient.introspectToken(req.headers['x-proof-token']);
if (!tokenInfo.valid) {
  return res.status(401).json({ error: 'Invalid' });
}
```

### 2. 타임아웃 설정

```typescript
// ❌ 위험: 타임아웃 없음
const client = new HashGuardClient({ baseUrl: '...' });

// ✅ 안전: 명시적 타임아웃
const client = new HashGuardClient({
  baseUrl: '...',
  timeout: 30_000, // 30초 네트워크 타임아웃
});

const result = await client.execute('login', {
  timeoutMs: 120_000, // 2분 PoW 계산 타임아웃
});
```

### 3. 환경 변수 사용

```typescript
// ❌ 위험: 하드코딩
const client = new HashGuardClient({
  baseUrl: 'https://pow.example.com',
});

// ✅ 안전: 환경에서 읽기
const client = new HashGuardClient({
  baseUrl: process.env.HASHGUARD_URL || 'https://pow.example.com',
  headers: {
    Authorization: `Bearer ${process.env.HASHGUARD_API_KEY}`,
  },
});
```

### 4. IP 검증

```typescript
// 백엔드에서 추가 검증
const tokenInfo = await powClient.introspectToken(proofToken);

// 토큰 발급 IP와 현재 요청 IP 비교
const clientIp = getClientIp(req);
if (tokenInfo.subject !== clientIp) {
  console.warn(`IP mismatch: token=${tokenInfo.subject}, request=${clientIp}`);
  return res.status(403).json({ error: 'IP mismatch' });
}
```

---

## 🧪 테스트 예제

```typescript
import { HashGuardClient, solvePow } from '@hashguard/client';

describe('HashGuard Integration', () => {
  const client = new HashGuardClient({
    baseUrl: 'http://localhost:3000',
  });

  it('should complete full PoW workflow', async () => {
    const result = await client.execute('test');

    expect(result.challenge.challengeId).toBeDefined();
    expect(result.solveResult.nonce).toBeDefined();
    expect(result.solveResult.attempts).toBeGreaterThan(0);
    expect(result.verification.proofToken).toBeDefined();
  });

  it('should verify proof token', async () => {
    const result = await client.execute('test');
    const tokenInfo = await client.introspectToken(result.verification.proofToken);

    expect(tokenInfo.valid).toBe(true);
    expect(tokenInfo.context).toBe('test');
  });

  it('should handle solver timeout', async () => {
    const result = await client.issueChallenge('test');

    // 불가능한 목표값으로 timeout 유도
    const impossibleTarget = '0'.repeat(64);

    expect(() => {
      solvePow(result.challengeId, result.seed, impossibleTarget, {
        maxAttempts: 100,
        timeoutMs: 1000,
      });
    }).toThrow('PoW solver gave up');
  });
});
```

---

## 📚 추가 리소스

- [SDK GitHub Repository](https://github.com/vientorepublic/hashguard)
- [Proof-of-Work 개념](https://en.bitcoin.it/wiki/Proof_of_work)
- [API 문서](../hashguard-analysis.md)
- [타입스크립트 문서](https://www.typescriptlang.org/)
