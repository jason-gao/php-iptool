<?php

//https://www.php.net/manual/zh/function.inet-pton.php
//支持ipv4和ipv6

namespace IpTool;

use IPTools\Network;

class IpUtils {

	private static $checkedIps = [];

	/**
	 * This class should not be instantiated.
	 */
	private function __construct() {
	}

	/**
	 * Checks if an IPv4 or IPv6 address is contained in the list of given IPs or subnets.
	 *
	 * @param string|array $ips List of IPs or subnets (can be a string if only a single one)
	 *
	 * @return bool Whether the IP is valid
	 */
	public static function checkIp( $requestIp, $ips ) {
		if ( ! is_array( $ips ) ) {
			$ips = [ $ips ];
		}

		$method = substr_count( $requestIp, ':' ) > 1 ? 'checkIp6' : 'checkIp4';

		foreach ( $ips as $ip ) {
			if ( self::$method( $requestIp, $ip ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Compares two IPv4 addresses.
	 * In case a subnet is given, it checks if it contains the request IP.
	 *
	 * @param string $ip IPv4 address or subnet in CIDR notation
	 *
	 * @return bool Whether the request IP matches the IP, or whether the request IP is within the CIDR subnet
	 */
	public static function checkIp4( $requestIp, $ip ) {
		$cacheKey = $requestIp . '-' . $ip;
		if ( isset( self::$checkedIps[ $cacheKey ] ) ) {
			return self::$checkedIps[ $cacheKey ];
		}

		if ( ! filter_var( $requestIp, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
			return self::$checkedIps[ $cacheKey ] = false;
		}

		if ( self::validIpRange( $ip ) ) {
			return self::ipInRange( $requestIp, $ip );
		}

		if ( false !== strpos( $ip, '/' ) ) {
			list( $address, $netmask ) = explode( '/', $ip, 2 );

			if ( '0' === $netmask ) {
				return self::$checkedIps[ $cacheKey ] = filter_var( $address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 );
			}

			if ( $netmask < 0 || $netmask > 32 ) {
				return self::$checkedIps[ $cacheKey ] = false;
			}
		} else {
			$address = $ip;
			$netmask = 32;
		}

		if ( false === ip2long( $address ) ) {
			return self::$checkedIps[ $cacheKey ] = false;
		}

		return self::$checkedIps[ $cacheKey ] = 0 === substr_compare( sprintf( '%032b', ip2long( $requestIp ) ), sprintf( '%032b', ip2long( $address ) ), 0, $netmask );
	}

	/**
	 * Compares two IPv6 addresses.
	 * In case a subnet is given, it checks if it contains the request IP.
	 *
	 * @param string $ip IPv6 address or subnet in CIDR notation
	 *
	 * @return bool Whether the IP is valid
	 *
	 * @throws \RuntimeException When IPV6 support is not enabled
	 * @see https://github.com/dsp/v6tools
	 *
	 * @author David Soria Parra <dsp at php dot net>
	 *
	 */
	public static function checkIp6( $requestIp, $ip ) {
		$cacheKey = $requestIp . '-' . $ip;
		if ( isset( self::$checkedIps[ $cacheKey ] ) ) {
			return self::$checkedIps[ $cacheKey ];
		}

		if ( ! ( ( extension_loaded( 'sockets' ) && defined( 'AF_INET6' ) ) || inet_pton( '::1' ) ) ) {
			throw new \RuntimeException( 'Unable to check Ipv6. Check that PHP was not compiled with option "disable-ipv6".' );
		}

		if ( false !== strpos( $ip, '/' ) ) {
			list( $address, $netmask ) = explode( '/', $ip, 2 );

			if ( '0' === $netmask ) {
				return (bool) unpack( 'n*', inet_pton( $address ) );
			}

			if ( $netmask < 1 || $netmask > 128 ) {
				return self::$checkedIps[ $cacheKey ] = false;
			}
		} else {
			$address = $ip;
			$netmask = 128;
		}

		$bytesAddr = unpack( 'n*', inet_pton( $address ) );
		$bytesTest = unpack( 'n*', inet_pton( $requestIp ) );

		if ( ! $bytesAddr || ! $bytesTest ) {
			return self::$checkedIps[ $cacheKey ] = false;
		}

		for ( $i = 1, $ceil = ceil( $netmask / 16 ); $i <= $ceil; ++ $i ) {
			$left = $netmask - 16 * ( $i - 1 );
			$left = ( $left <= 16 ) ? $left : 16;
			$mask = ~( 0xffff >> $left ) & 0xffff;
			if ( ( $bytesAddr[ $i ] & $mask ) != ( $bytesTest[ $i ] & $mask ) ) {
				return self::$checkedIps[ $cacheKey ] = false;
			}
		}

		return self::$checkedIps[ $cacheKey ] = true;
	}

	/**
	 * Anonymizes an IP/IPv6.
	 *
	 * Removes the last byte for v4 and the last 8 bytes for v6 IPs
	 */
	public static function anonymize( $ip ) {
		$wrappedIPv6 = false;
		if ( '[' === substr( $ip, 0, 1 ) && ']' === substr( $ip, - 1, 1 ) ) {
			$wrappedIPv6 = true;
			$ip          = substr( $ip, 1, - 1 );
		}

		$packedAddress = inet_pton( $ip );
		if ( 4 === strlen( $packedAddress ) ) {
			$mask = '255.255.255.0';
		} elseif ( $ip === inet_ntop( $packedAddress & inet_pton( '::ffff:ffff:ffff' ) ) ) {
			$mask = '::ffff:ffff:ff00';
		} elseif ( $ip === inet_ntop( $packedAddress & inet_pton( '::ffff:ffff' ) ) ) {
			$mask = '::ffff:ff00';
		} else {
			$mask = 'ffff:ffff:ffff:ffff:0000:0000:0000:0000';
		}
		$ip = inet_ntop( $packedAddress & inet_pton( $mask ) );

		if ( $wrappedIPv6 ) {
			$ip = '[' . $ip . ']';
		}

		return $ip;
	}


	/**
	 * @param $ip
	 *
	 * @return int
	 * @throws \Exception
	 *
	 * 验证ip格式，并且返回ip版本
	 */
	public static function getIpVersion( $ip ) {
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return 0;
		}
		$in_addr = inet_pton( $ip );

		$version = 0;

		if ( filter_var( inet_ntop( $in_addr ), FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
			$version = 4;
		} elseif ( filter_var( inet_ntop( $in_addr ), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
			$version = 6;
		}

		return $version;
	}

	/**
	 * @param $ip
	 *
	 * @return bool
	 * @throws \Exception
	 * 检测是否是合法的ip地址
	 */
	public static function validIp( $ip ) {
		if ( self::getIpVersion( $ip ) != 0 ) {
			return true;
		}

		return false;
	}


	/**
	 * @param $cidr
	 *
	 * @return array
	 * 根据cidr获取ip列表
	 */
	public static function getIpsCidr( $cidr ) {
		$network = Network::parse( $cidr );
		$ips     = [];
		foreach ( $network as $ip ) {
			$ips[] = (string) $ip;
		}

		return $ips;
	}


	/**
	 * @param $ipRange 1.1.1.1-10
	 * @param string $separate
	 *
	 * @return bool
	 * @throws \Exception
	 */
	public static function validIpRange( $ipRange, $separate = '-' ) {
		if ( ! self::isIpRange($ipRange, $separate) ) {
			return false;
		}
		list( $pre, $end ) = explode( $separate, $ipRange );
		if ( $end > 255 ) {
			return false;
		}
		if ( ! self::validIp( $pre ) ) {
			return false;
		}
		list( $a, $b, $c, $d ) = explode( '.', $pre );

		if ( $end < $d ) {
			return false;
		}

		return true;
	}

	public static function isIpRange($ipRange, $separate = '-' ){
		$match = preg_match( '/^\d+\.\d+\.\d+\.\d+' . $separate . '\d+$/', $ipRange );

		return $match;
	}

	/**
	 * @param $ipRange 1.1.1.1-10  1.1.1.1,1.1.1.2
	 * @param string $separate
	 *
	 * @return array|bool|string
	 * @throws \Exception
	 */
	public static function getIpsRange( $ipRange, $separate = '-' ) {
		if ( ! self::validIpRange( $ipRange ) ) {
			return false;
		}

		$ips = [];
		list( $pre, $end ) = explode( $separate, $ipRange );
		list( $a, $b, $c, $d ) = explode( '.', $pre );

		if ( $end == $d ) {
			return "$a.$b.$c.$d";
		}

		for ( $i = $d; $i <= $end; $i ++ ) {
			$ip    = "$a.$b.$c.$i";
			$ips[] = $ip;
		}

		return $ips;
	}


	public static function ipInRange( $ip, $ipRange, $separate = '-' ) {
		if ( ! self::validIpRange( $ipRange ) ) {
			return false;
		}

		$ip = (float) sprintf( '%u', ip2long( $ip ) );

		list( $pre, $end ) = explode( $separate, $ipRange );
		list( $a, $b, $c, $d ) = explode( '.', $pre );

		$begin = (float) sprintf( '%u', ip2long( trim( "$a.$b.$c.$d" ) ) );
		$end   = (float) sprintf( '%u', ip2long( trim( "$a.$b.$c.$end" ) ) );


		if ( $ip >= $begin && $ip <= $end ) {
			return true;
		}

		return false;
	}

	/**
	 * @param $ip_block
	 * @param string $separate
	 *
	 * @return bool
	 * @node_name ip段前3个必须相同
	 * @link
	 * @desc
	 */
	public static function ipBlockPreThreeSame( $ip_block, $separate = '-' ) {
		if ( false === stripos( $ip_block, $separate ) ) {
			return false;
		}
		list( $pre, $end ) = explode( $separate, $ip_block );
		list( $a, $b, $c, $d ) = explode( '.', $pre );
		list( $a1, $b1, $c1, $d1 ) = explode( '.', $end );

		if ( ( $a != $a1 ) || ( $b != $b1 ) || ( $c != $c1 ) ) {
			return false;
		}

		if ( $d == $d1 ) {
			return false;
		}

		return true;
	}

	/**
	 * @param $ip
	 *
	 * @return bool
	 *
	 * 是否是cidr
	 */
	public static function isCidr( $ip ) {
		if ( false !== strpos( $ip, '/' ) ) {
			return true;
		}

		return false;
	}


	/**
	 * @param $ip
	 *
	 * @return bool|mixed
	 * @throws \Exception
	 *
	 * cidr是否合法
	 */
	public static function validCidr( $ip ) {
		if ( self::isCidr( $ip ) ) {
			list( $address, $netmask ) = explode( '/', $ip, 2 );
			if ( self::getIpVersion( $address ) == 4 ) {
				if ( '0' === $netmask ) {
					return filter_var( $address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 );
				}

				if ( $netmask < 0 || $netmask > 32 ) {
					return false;
				}

				if ( false === ip2long( $address ) ) {
					return false;
				}

				return true;
			} else {
				if ( '0' === $netmask ) {
					return (bool) unpack( 'n*', inet_pton( $address ) );
				}

				if ( $netmask < 1 || $netmask > 128 ) {
					return false;
				}

				$bytesAddr = unpack( 'n*', inet_pton( $address ) );

				if ( ! $bytesAddr ) {
					return false;
				}

				return true;
			}
		}

		return false;
	}


}