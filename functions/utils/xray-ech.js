export function adaptXrayEchSubscription(content, userAgent) {
    if (!/\bv2rayn(?:g)?\b/i.test(userAgent || '')) return content;
    const domain = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;
    return content.split(/(\r?\n)/).map((line) => {
        if (!line.startsWith('vless://')) return line;
        try {
            const url = new URL(line);
            const value = url.searchParams.get('ech');
            if (url.searchParams.get('security') !== 'tls' || !domain.test(value || '')) return line;
            // Xray treats a bare hostname as a static Base64 key, unlike Mihomo's query-server-name.
            const query = value + '+https://dns.alidns.com/dns-query';
            return line.replace(/([?&]ech=)[^&#]*/, (_, prefix) => prefix + encodeURIComponent(query));
        } catch {
            return line;
        }
    }).join('');
}
