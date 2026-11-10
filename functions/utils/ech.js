const DOMAIN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;

export function parseEchParams(params) {
    const value = (params.get('ech') || '').trim();
    const config = (params.get('ech-config') || '').trim();
    if (!value && !config) return undefined;
    if (['0', 'false', 'off'].includes(value.toLowerCase()) && !config) return undefined;
    const result = { enable: true };
    let encodedConfig = config;
    if (value && !['1', 'true', 'on'].includes(value.toLowerCase())) {
        if (DOMAIN.test(value)) result['query-server-name'] = value;
        else if (!encodedConfig) encodedConfig = value;
        else throw new Error('Invalid ECH query domain');
    }
    if (encodedConfig) {
        if (encodedConfig.length > 8192 || !/^[A-Za-z0-9+/]+={0,2}$/.test(encodedConfig))
            throw new Error('Invalid ECH config');
        const decoded = atob(encodedConfig);
        if (decoded.length < 8 || decoded.charCodeAt(2) !== 0xfe || decoded.charCodeAt(3) !== 0x0d)
            throw new Error('Invalid ECH config');
        result.config = encodedConfig;
    }
    return result;
}

export function appendEchParams(params, opts) {
    if (!opts || opts.enable !== true) return;
    params.push(`ech=${encodeURIComponent(opts['query-server-name'] || '1')}`);
    if (opts.config) params.push(`ech-config=${encodeURIComponent(opts.config)}`);
}

export function withEchDnsPolicies(dns, proxies) {
    const required = proxies.some((node) => {
        const opts = node['ech-opts'];
        return (
            opts?.enable === true &&
            !opts.config &&
            opts['query-server-name'] === 'cloudflare-ech.com'
        );
    });
    if (!required) return dns;
    const result = structuredClone(dns);
    for (const key of ['nameserver-policy', 'proxy-server-nameserver-policy']) {
        result[key] ||= {};
        result[key]['cloudflare-ech.com'] ??= ['https://dns.alidns.com/dns-query#DIRECT'];
    }
    return result;
}
