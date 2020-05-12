<?php

declare(strict_types=1);

namespace SAML2;

/**
 * Helper functions for the SAML2 library.
 *
 * @package SimpleSAMLphp
 */
class Utils
{
   /**
     * This function converts a SAML2 timestamp on the form
     * yyyy-mm-ddThh:mm:ss(\.s+)?Z to a UNIX timestamp. The sub-second
     * part is ignored.
     *
     * Andreas comments:
     *  I got this timestamp from Shibboleth 1.3 IdP: 2008-01-17T11:28:03.577Z
     *  Therefore I added to possibility to have microseconds to the format.
     * Added: (\.\\d{1,3})? to the regex.
     *
     * Note that we always require a 'Z' timezone for the dateTime to be valid.
     * This is not in the SAML spec but that's considered to be a bug in the
     * spec. See https://github.com/simplesamlphp/saml2/pull/36 for some
     * background.
     *
     * @param string $time The time we should convert.
     * @throws \Exception
     * @return int Converted to a unix timestamp.
     */
    public static function xsDateTimeToTimestamp(string $time): int
    {
        $matches = [];

        // We use a very strict regex to parse the timestamp.
        $regex = '/^(\\d\\d\\d\\d)-(\\d\\d)-(\\d\\d)T(\\d\\d):(\\d\\d):(\\d\\d)(?:\\.\\d{1,9})?Z$/D';
        if (preg_match($regex, $time, $matches) == 0) {
            throw new InvalidArgumentException(
                'Invalid SAML2 timestamp passed to xsDateTimeToTimestamp: ' . $time
            );
        }

        // Extract the different components of the time from the  matches in the regex.
        // intval will ignore leading zeroes in the string.
        $year   = intval($matches[1]);
        $month  = intval($matches[2]);
        $day    = intval($matches[3]);
        $hour   = intval($matches[4]);
        $minute = intval($matches[5]);
        $second = intval($matches[6]);

        // We use gmmktime because the timestamp will always be given
        //in UTC.
        $ts = gmmktime($hour, $minute, $second, $month, $day, $year);

        return $ts;
    }


    /**
     * @return \SAML2\Compat\ContainerInterface
     */
    public static function getContainer(): ContainerInterface
    {
        return ContainerSingleton::getInstance();
    }
}

