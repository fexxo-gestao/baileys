import { lookup } from 'node:dns/promises'
import { BlockList, isIP } from 'node:net'

/** Thrown when a link preview would fetch a loopback, private or otherwise internal address (SSRF guard) */
export class PrivateAddressError extends Error {
	constructor(readonly hostname: string) {
		super(`link preview blocked: ${hostname} resolves to a non-public address`)
		this.name = 'PrivateAddressError'
	}
}

const NON_PUBLIC = new BlockList()
for (const [network, prefix] of [
	['0.0.0.0', 8],
	['10.0.0.0', 8],
	['100.64.0.0', 10],
	['127.0.0.0', 8],
	['169.254.0.0', 16],
	['172.16.0.0', 12],
	['192.0.0.0', 24],
	['192.168.0.0', 16],
	['198.18.0.0', 15],
	['224.0.0.0', 4],
	['240.0.0.0', 4]
] as const) {
	NON_PUBLIC.addSubnet(network, prefix, 'ipv4')
}

for (const [network, prefix] of [
	['::', 128],
	['::1', 128],
	['fc00::', 7],
	['fe80::', 10],
	['ff00::', 8]
] as const) {
	NON_PUBLIC.addSubnet(network, prefix, 'ipv6')
}

const unwrapMappedIPv4 = (address: string) => {
	const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(address)
	return mapped ? mapped[1]! : address
}

/** True when the IP literal is loopback, private, link-local, CGNAT, multicast or reserved */
export const isNonPublicAddress = (address: string) => {
	const ip = unwrapMappedIPv4(address.replace(/^\[|\]$/g, ''))
	const family = isIP(ip)
	if (family === 0) {
		return true
	}

	return NON_PUBLIC.check(ip, family === 4 ? 'ipv4' : 'ipv6')
}

type Resolver = (hostname: string) => Promise<{ address: string }[]>

const resolveAll: Resolver = hostname => lookup(hostname, { all: true, verbatim: true })

/**
 * Resolves the URL host and returns its first address, refusing hosts where ANY resolved
 * address is internal. Meant for link-preview-js `resolveDNSHost`.
 */
export const resolvePublicHost = async (url: string, resolve: Resolver = resolveAll) => {
	const hostname = new URL(url).hostname.replace(/^\[|\]$/g, '')
	const addresses = isIP(hostname) ? [{ address: hostname }] : await resolve(hostname)
	if (!addresses.length || addresses.some(({ address }) => isNonPublicAddress(address))) {
		throw new PrivateAddressError(hostname)
	}

	return addresses[0]!.address
}

/** Same check as {@link resolvePublicHost}, as a boolean, for URLs fetched outside link-preview-js */
export const isPublicUrl = async (url: string, resolve: Resolver = resolveAll) => {
	try {
		const { protocol } = new URL(url)
		if (protocol !== 'https:' && protocol !== 'http:') {
			return false
		}

		await resolvePublicHost(url, resolve)
		return true
	} catch {
		return false
	}
}
