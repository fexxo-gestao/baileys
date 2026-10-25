import { getUrlInfo } from '../../Utils/link-preview'
import { isNonPublicAddress, isPublicUrl, PrivateAddressError, resolvePublicHost } from '../../Utils/public-host'

const resolvingTo =
	(...addresses: string[]) =>
	async () =>
		addresses.map(address => ({ address }))

describe('isNonPublicAddress', () => {
	it.each([
		'127.0.0.1',
		'10.43.0.1',
		'172.16.5.4',
		'172.31.255.255',
		'192.168.0.10',
		'169.254.169.254',
		'100.64.0.1',
		'0.0.0.0',
		'::1',
		'::',
		'fd00::1',
		'fe80::1',
		'::ffff:127.0.0.1',
		'::ffff:10.0.0.1',
		'[::1]',
		'not-an-ip'
	])('blocks %s', address => {
		expect(isNonPublicAddress(address)).toBe(true)
	})

	it.each(['8.8.8.8', '172.32.0.1', '201.23.66.13', '2606:4700:4700::1111', '::ffff:8.8.8.8'])('allows %s', address => {
		expect(isNonPublicAddress(address)).toBe(false)
	})
})

describe('resolvePublicHost', () => {
	it('returns the first address of a public host', async () => {
		await expect(resolvePublicHost('https://example.com/a', resolvingTo('93.184.216.34'))).resolves.toBe(
			'93.184.216.34'
		)
	})

	it('refuses an IP literal that is internal', async () => {
		await expect(resolvePublicHost('http://169.254.169.254/latest/meta-data')).rejects.toBeInstanceOf(
			PrivateAddressError
		)
		await expect(resolvePublicHost('http://[::1]:3000/metrics')).rejects.toBeInstanceOf(PrivateAddressError)
	})

	it('refuses a host when any of its DNS answers is internal (rebinding-style split answers)', async () => {
		await expect(
			resolvePublicHost('https://evil.example/x', resolvingTo('93.184.216.34', '10.43.0.10'))
		).rejects.toBeInstanceOf(PrivateAddressError)
	})

	it('refuses a host that resolves to nothing', async () => {
		await expect(resolvePublicHost('https://empty.example', resolvingTo())).rejects.toBeInstanceOf(PrivateAddressError)
	})
})

describe('isPublicUrl', () => {
	it('is false for internal hosts and non-http schemes', async () => {
		await expect(isPublicUrl('http://127.0.0.1/og.png')).resolves.toBe(false)
		await expect(isPublicUrl('file:///etc/passwd')).resolves.toBe(false)
		await expect(isPublicUrl('not a url')).resolves.toBe(false)
	})

	it('is true for a public host', async () => {
		await expect(isPublicUrl('https://cdn.example/og.png', resolvingTo('93.184.216.34'))).resolves.toBe(true)
	})
})

describe('getUrlInfo SSRF guard', () => {
	it('sends the message without preview instead of fetching an internal address', async () => {
		const logger = { warn: () => {}, debug: () => {} } as never

		await expect(
			getUrlInfo('http://127.0.0.1:9/metrics', { thumbnailWidth: 192, fetchOpts: { timeout: 1000 }, logger })
		).resolves.toBeUndefined()
		await expect(
			getUrlInfo('http://169.254.169.254/latest/meta-data/', {
				thumbnailWidth: 192,
				fetchOpts: { timeout: 1000 },
				logger
			})
		).resolves.toBeUndefined()
	})
})
