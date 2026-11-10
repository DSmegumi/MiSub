import { describe, it, expect } from 'vitest';
import yaml from 'js-yaml';
import { urlToClashProxy } from '../../functions/utils/url-to-clash.js';
import { convertClashProxyToUrl } from '../../functions/utils/clash-to-url.js';
import { generateBuiltinClashConfig } from '../../functions/modules/subscription/builtin-clash-generator.js';
import { renderClashFromTemplateModel } from '../../functions/modules/subscription/template-renderers/render-clash.js';

const base =
    'vless://00000000-0000-4000-8000-000000000001@104.18.25.253:2083?security=tls&type=xhttp&sni=owned.example.com&host=owned.example.com&path=%2Ftest%2F&mode=packet-up#CSS-backup';
const ech = base.replace('#', '&ech=cloudflare-ech.com#');
const resolver = ['https://dns.alidns.com/dns-query#DIRECT'];

describe('ECH subscription preservation', () => {
    it('parses dynamic ECH without disabling certificate verification', () => {
        const node = urlToClashProxy(ech);
        expect(node['ech-opts']).toEqual({
            enable: true,
            'query-server-name': 'cloudflare-ech.com',
        });
        expect(node['skip-cert-verify']).not.toBe(true);
    });
    it('round trips ECH and IPv6 through share links', () => {
        const node = urlToClashProxy(ech);
        node.server = '2606:4700::6812:a76';
        expect(node['ech-opts']).toEqual({
            enable: true,
            'query-server-name': 'cloudflare-ech.com',
        });
        const after = urlToClashProxy(convertClashProxyToUrl(node));
        expect(after.server).toBe(node.server);
        expect(after['ech-opts']).toEqual(node['ech-opts']);
        expect(after['xhttp-opts']).toEqual(node['xhttp-opts']);
    });
    it('adds only exact ECH DNS policies to builtin output', () => {
        const before = yaml.load(generateBuiltinClashConfig(base));
        const after = yaml.load(generateBuiltinClashConfig(ech));
        expect(after.dns['nameserver-policy']['cloudflare-ech.com']).toEqual(resolver);
        expect(after.dns['proxy-server-nameserver-policy']['cloudflare-ech.com']).toEqual(resolver);
        delete after.dns['nameserver-policy']['cloudflare-ech.com'];
        delete after.dns['proxy-server-nameserver-policy'];
        expect(after.dns).toEqual(before.dns);
        expect(after.rules).toEqual(before.rules);
        expect(after['proxy-groups']).toEqual(before['proxy-groups']);
    });
    it('also preserves ECH bootstrap in custom template output', () => {
        const node = urlToClashProxy(ech);
        const output = yaml.load(
            renderClashFromTemplateModel({ proxies: [node], groups: [], rules: [] })
        );
        expect(output.proxies[0]['ech-opts']).toEqual(node['ech-opts']);
        expect(output.dns['nameserver-policy']['cloudflare-ech.com']).toEqual(resolver);
    });
    it('preserves explicit static configs with plus signs', () => {
        const config =
            'AEX+DQBBYAAgACCNBVf6r1qY1+aiasUdqoL0UCnFv3azXuPXYZj4J3gzPQAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA=';
        const node = urlToClashProxy(base.replace('#', '&ech=' + encodeURIComponent(config) + '#'));
        expect(node['ech-opts']).toEqual({ enable: true, config });
        expect(urlToClashProxy(convertClashProxyToUrl(node))['ech-opts']).toEqual(node['ech-opts']);
    });
    it('requires ordinary TLS when ECH is requested', () => {
        expect(urlToClashProxy(ech.replace('security=tls', 'security=none'))).toBeNull();
    });
    it('does not add ECH or DNS policies to ordinary subscriptions', () => {
        const output = yaml.load(generateBuiltinClashConfig(base));
        expect(output.proxies[0]['ech-opts']).toBeUndefined();
        expect(output.dns['nameserver-policy']['cloudflare-ech.com']).toBeUndefined();
    });
    it('rejects malformed requested ECH instead of silently using plaintext SNI', () => {
        expect(urlToClashProxy(base.replace('#', '&ech=invalid%20configuration#'))).toBeNull();
    });
});
