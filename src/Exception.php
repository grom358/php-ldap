<?php
namespace Ldap;

/**
 * LDAP Exception.
 */
class Exception extends \Exception
{
    /**
     * LDAP Exception.
     *
     * @param string $message
     *   Error message.
     * @param int $code
     *   Error code.
     */
    public function __construct($message, $code = 0)
    {
        parent::__construct($message, $code);
    }

    public function __toString()
    {
        $error = __CLASS__ . ": Error code  {$this->code}:  {$this->message}\n";
        $error .= "Stack trace:\n";
        $count = 0;
        foreach ($this->getTrace() as $t) {
            if ($t['file'] != __FILE__) {
                $error .= '#' . $count . ' ' . $t['file'] . '(' . $t['line'] . '): ' . $t['class'] . $t['type'] . $t['function'] . '(' . implode(', ', $t['args']) . ")\n";
                $count++;
            }
        }
        return $error;
    }

    /**
     * Check for ldap errors.
     *
     * @param resource $ds
     *   LDAP connection resource.
     *
     * @throws Exception
     */
    static public function checkForLdapError($ds)
    {
        if ($errorCode = ldap_errno($ds)) {
            throw new Exception(ldap_error($ds), $errorCode);
        }
    }
}
