import { describe, it, expect } from 'vitest';
import { adaptXrayEchSubscription } from '../../functions/utils/xray-ech.js';

const line = 'vless://00000000-0000-4000-8000-000000000001@preferred.example.com:2083?security=tls&type=xhttp&sni=owned.example.com&path=%2Ftest%2F&ech=cloudflare-ech.com#node';
const expected = 'cloudflare-ech.com+https://dns.alidns.com/dns-query';

describe('Xray client ECH subscription format', () => {
    for (const agent of ['v2rayNG/2.3.14', 'v2rayN/7.23']) {
        it(`emits a real DNS lookup expression for ${agent}`, () => {
            const output = adaptXrayEchSubscription(line, agent);
            expect(new URL(output).searchParams.get('ech')).toBe(expected);
            expect(output.replace(/ech=[^&#]*/, 'ech=cloudflare-ech.com')).toBe(line);
        });
    }
    it('keeps Mihomo and other client output byte identical', () => {
        for (const agent of ['Clash.Meta', 'clash-verge/v2.4.2', 'Shadowrocket', ''])
            expect(adaptXrayEchSubscription(line, agent)).toBe(line);
    });
    it('preserves already configured lookup expressions and static keys', () => {
        for (const value of [expected, 'AEX+DQBBYAAgACCNBVf6r1qY1+aiasUdqoL0UCnFv3azXuPXYZj4J3gzPQAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA=']) {
            const input = line.replace('ech=cloudflare-ech.com', 'ech=' + encodeURIComponent(value));
            expect(adaptXrayEchSubscription(input, 'v2rayNG/2.3.14')).toBe(input);
        }
    });
    it('does not change unrelated lines, transport or newline layout', () => {
        const other = 'hysteria2://test-only@example.com:443#other';
        const input = other + '\r\n' + line + '\r\n';
        const output = adaptXrayEchSubscription(input, 'v2rayNG/2.3.14');
        expect(output.split('\r\n')[0]).toBe(other);
        expect(output.endsWith('\r\n')).toBe(true);
        expect(new URL(output.split('\r\n')[1]).searchParams.get('ech')).toBe(expected);
    });
});
