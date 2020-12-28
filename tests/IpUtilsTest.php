<?php


namespace Tests;

use IpTool\IpUtils;

class IpUtilsTest extends TestCase {

	/**
	 * @dataProvider getIpv4Data
	 */
	public function testIpv4( $matches, $remoteAddr, $cidr ) {
		$this->assertSame( $matches, IpUtils::checkIp( $remoteAddr, $cidr ) );
	}

	public function getIpv4Data() {
		return [
			[ true, '192.168.1.1', '192.168.1.1' ],
			[ true, '192.168.1.1', '192.168.1.1/1' ],
			[ true, '192.168.1.1', '192.168.1.0/24' ],
			[ false, '192.168.1.1', '1.2.3.4/1' ],
			[ false, '192.168.1.1', '192.168.1.1/33' ], // invalid subnet
			[ true, '192.168.1.1', [ '1.2.3.4/1', '192.168.1.0/24' ] ],
			[ true, '192.168.1.1', [ '192.168.1.0/24', '1.2.3.4/1' ] ],
			[ false, '192.168.1.1', [ '1.2.3.4/1', '4.3.2.1/1' ] ],
			[ true, '1.2.3.4', '0.0.0.0/0' ],
			[ true, '1.2.3.4', '192.168.1.0/0' ],
			[ false, '1.2.3.4', '256.256.256/0' ], // invalid CIDR notation
			[ false, 'an_invalid_ip', '192.168.1.0/24' ],
			[ true, '1.1.1.1', '1.1.1.1-10' ],
			[ true, '1.1.1.1', [ '1.1.1.3', '1.1.1.1-255' ] ],
		];
	}

	/**
	 * @dataProvider getIpv6Data
	 */
	public function testIpv6( $matches, $remoteAddr, $cidr ) {
		if ( ! defined( 'AF_INET6' ) ) {
			$this->markTestSkipped( 'Only works when PHP is compiled without the option "disable-ipv6".' );
		}

		$this->assertSame( $matches, IpUtils::checkIp( $remoteAddr, $cidr ) );
	}

	public function getIpv6Data() {
		return [
			[ true, '2a01:198:603:0:396e:4789:8e99:890f', '2a01:198:603:0::/65' ],
			[ false, '2a00:198:603:0:396e:4789:8e99:890f', '2a01:198:603:0::/65' ],
			[ false, '2a01:198:603:0:396e:4789:8e99:890f', '::1' ],
			[ true, '0:0:0:0:0:0:0:1', '::1' ],
			[ false, '0:0:603:0:396e:4789:8e99:0001', '::1' ],
			[ true, '0:0:603:0:396e:4789:8e99:0001', '::/0' ],
			[ true, '0:0:603:0:396e:4789:8e99:0001', '2a01:198:603:0::/0' ],
			[ true, '2a01:198:603:0:396e:4789:8e99:890f', [ '::1', '2a01:198:603:0::/65' ] ],
			[ true, '2a01:198:603:0:396e:4789:8e99:890f', [ '2a01:198:603:0::/65', '::1' ] ],
			[ false, '2a01:198:603:0:396e:4789:8e99:890f', [ '::1', '1a01:198:603:0::/65' ] ],
			[ false, '}__test|O:21:&quot;JDatabaseDriverMysqli&quot;:3:{s:2', '::1' ],
			[ false, '2a01:198:603:0:396e:4789:8e99:890f', 'unknown' ],
		];
	}

	/**
	 * @requires extension sockets
	 */
	public function testAnIpv6WithOptionDisabledIpv6() {
		$this->expectException( 'RuntimeException' );
		if ( defined( 'AF_INET6' ) ) {
			$this->markTestSkipped( 'Only works when PHP is compiled with the option "disable-ipv6".' );
		}

		IpUtils::checkIp( '2a01:198:603:0:396e:4789:8e99:890f', '2a01:198:603:0::/65' );
	}

	/**
	 * @dataProvider invalidIpAddressData
	 */
	public function testInvalidIpAddressesDoNotMatch( $requestIp, $proxyIp ) {
		$this->assertFalse( IpUtils::checkIp4( $requestIp, $proxyIp ) );
	}

	public function invalidIpAddressData() {
		return [
			'invalid proxy wildcard'                         => [ '192.168.20.13', '*' ],
			'invalid proxy missing netmask'                  => [ '192.168.20.13', '0.0.0.0' ],
			'invalid request IP with invalid proxy wildcard' => [ '0.0.0.0', '*' ],
		];
	}

	/**
	 * @dataProvider anonymizedIpData
	 */
	public function testAnonymize( $ip, $expected ) {
		$this->assertSame( $expected, IpUtils::anonymize( $ip ) );
	}

	public function anonymizedIpData() {
		return [
			[ '192.168.1.1', '192.168.1.0' ],
			[ '1.2.3.4', '1.2.3.0' ],
			[ '2a01:198:603:0:396e:4789:8e99:890f', '2a01:198:603::' ],
			[ '2a01:198:603:10:396e:4789:8e99:890f', '2a01:198:603:10::' ],
			[ '::1', '::' ],
			[ '0:0:0:0:0:0:0:1', '::' ],
			[ '1:0:0:0:0:0:0:1', '1::' ],
			[ '0:0:603:50:396e:4789:8e99:0001', '0:0:603:50::' ],
			[ '[0:0:603:50:396e:4789:8e99:0001]', '[0:0:603:50::]' ],
			[ '[2a01:198::3]', '[2a01:198::]' ],
			[ '::ffff:123.234.235.236', '::ffff:123.234.235.0' ], // IPv4-mapped IPv6 addresses
			[ '::123.234.235.236', '::123.234.235.0' ], // deprecated IPv4-compatible IPv6 address
		];
	}

	/**
	 * @dataProvider ipData
	 */
	public function testValidIp( $match, $ip ) {
		$this->assertEquals( $match, IpUtils::validIp( $ip ) );
	}

	public function ipData() {
		return [
			[ true, '127.0.0.1' ],
			[ true, '255.255.255.0' ],
			[ true, '2001::' ],
			[ false, '11' ],
		];
	}


	/**
	 * @dataProvider ipVersionData
	 */
	public function testIpVersion( $match, $ip ) {
		$this->assertEquals( $match, IpUtils::getIpVersion( $ip ) );
	}

	public function ipVersionData() {
		return [
			[ 4, '127.0.0.1' ],
			[ 4, '255.255.255.0' ],
			[ 6, '2001::' ],
			[ 0, '11' ],
		];
	}

	public function testGetIpsCidr() {
		echo json_encode( IpUtils::getIpsCidr( '127.0.0.1/27' ) );
	}


	/**
	 * @dataProvider validCidrData
	 */
	public function testValidCidr( $match, $ip ) {
		$this->assertEquals( $match, IpUtils::validCidr( $ip ) );
	}

	public function validCidrData() {
		return [
			[ false, '127.0.0.1' ],
			[ true, '127.0.0.1/24' ],
			[ true, '2a01:198:603:0::/65' ],
			[ true, '210.13.52.67/32' ],
			[ true, '210.13.52.67/26' ],
		];
	}

	/**
	 * @dataProvider validRangeData
	 */
	public function testValidRange( $match, $ip ) {
		$this->assertEquals( $match, IpUtils::validIpRange( $ip ) );
	}

	public function validRangeData() {
		return [
			[ false, '1.1.1.1' ],
			[ true, '127.0.0.1-22' ],
			[ false, '1.1.1.10-1' ],
			[ true, '1.1.1.10-10' ],
		];
	}

	public function testRangeIps() {
		$range = "1.1.1.1-2";

		$ips = IpUtils::getIpsRange( $range );

		var_dump( $ips );
	}

}