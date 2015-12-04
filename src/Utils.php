<?php
namespace Ldap;

/**
 * LDAP Utility class.
 */
class Utils
{
    /**
     * Take an LDAP entry and make an associative array from it.
     *
     * This function takes an LDAP entry in the ldap_get_entries() style and
     * converts it to an associative array like ldap_add() needs.
     *
     * @param array $entry
     *   LDAP entry that to be converted.
     *
     * @return array
     *   The converted entry.
     */
    static public function cleanUpEntry(&$entry)
    {
        $retEntry = array();
        for ($i = 0; $i < $entry['count']; $i++) {
            $attribute = $entry[$i];
            if ($entry[$attribute]['count'] == 1) {
                $retEntry[$attribute] = $entry[$attribute][0];
            } else {
                for ($j = 0; $j < $entry[$attribute]['count']; $j++) {
                    $retEntry[$attribute][] = $entry[$attribute][$j];
                }
            }
        }
        return $retEntry;
    }

    /**
     * Read an LDAP entry.
     *
     * @param resource $ds
     *   LDAP connection resource.
     * @param resource $entryId
     *   LDAP entry resource.
     * @param string[] $binaryFields
     *   Names of binary attributes.
     *
     * @return array
     *   Attributes for an LDAP entry.
     */
    static public function readEntry($ds, $entryId, $binaryFields = array())
    {
        $data = array();
        for ($attribute = ldap_first_attribute($ds, $entryId, $attributeId); $attribute !== false; $attribute = ldap_next_attribute($ds, $entryId, $attributeId)) {
            $fieldValues = ldap_get_values($ds, $entryId, $attribute);
            if (in_array($attribute, $binaryFields)) {
                $fieldValues = ldap_get_values_len($ds, $entryId, $attribute);
            }
            if ($fieldValues['count'] == 1) {
                $data[$attribute] = $fieldValues[0];
            } else {
                for ($i = 0; $i < $fieldValues['count']; $i++) {
                    $data[$attribute][$i] = $fieldValues[$i];
                }
            }
        }
        return $data;
    }

    /**
     * Get an LDAP entry.
     *
     * @param resource $ds
     *   LDAP connection resource.
     * @param string $dn
     *   Fully qualified distinguished name of LDAP entry.
     * @param string[] $attributes
     *   Attributes to get.
     * @param array $binaryFields
     *   Names of binary attributes.
     *
     * @return array|null
     *   Attributes for an LDAP entry or null if not found.
     */
    static public function getEntry($ds, $dn, $attributes = array(), $binaryFields = array())
    {
        $sr = @ldap_read($ds, $dn, '(objectclass=*)', $attributes);
        if (!$sr) {
            return null;
        }
        $entryID = ldap_first_entry($ds, $sr);
        $entry = self::readEntry($ds, $entryID, $binaryFields);
        return $entry;
    }

    /**
     * Get the distinguished name of parent entry.
     *
     * @param string $dn
     *   Fully qualified distinguished name of LDAP entry.
     *
     * @return string
     *   Fully qualified distinguished name of parent LDAP entry.
     */
    static public function getParent($dn)
    {
        $exploded_dn = ldap_explode_dn($dn, 0);
        $path = array();
        for ($i = 1; $i < $exploded_dn['count']; $i++) {
            $path[] = $exploded_dn[$i];
        }
        return implode(',', $path);
    }

    /**
     * Test whether object class exists in objectclass attribute.
     *
     * @param string $class
     *   Object class to test for.
     * @param string[] $ldapClasses
     *   Array of object classes.
     *
     * @return bool
     *   Returns true if object class exists.
     */
    static public function hasClass($class, $ldapClasses)
    {
        if (in_array($class, $ldapClasses) || in_array(strtolower($class), $ldapClasses)) {
            return true;
        }
        return false;
    }

    /**
     * Extract out the roles from LDAP entry.
     *
     * @param resource $ds
     *   LDAP connection resource.
     * @param array $ldap_entry
     *   LDAP entry.
     *
     * @return array
     *   Array of roles.
     */
    static public function getRoles(&$ds, &$ldap_entry)
    {
        $roles = array();
        if (!$ldap_entry['nsRole']) {
            return $roles;
        }
        if (!is_array($ldap_entry['nsRole'])) {
            $ldap_entry['nsRole'] = array($ldap_entry['nsRole']);
        }
        foreach ($ldap_entry['nsRole'] as $dn) {
            $sr = ldap_read($ds, $dn, '(objectClass=*)', array('cn'));
            $entryId = ldap_first_entry($ds, $sr);
            $entry = self::cleanUpEntry(ldap_get_attributes($ds, $entryId));
            $roles[] = $entry['cn'];
        }
        return $roles;
    }

    /**
     * Get relative distinguished name.
     *
     * @param string $dn
     *   Fully qualified distinguished name.
     * @param $baseDN
     *   Base distinguished name.
     *
     * @return string
     *   Relative distinguished name.
     */
    static public function getRDN($dn, $baseDN)
    {
        return substr($dn, 0, strlen($dn) - strlen($baseDN) - 1);
    }
}
