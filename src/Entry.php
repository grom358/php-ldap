<?php
namespace Ldap;

/**
 * LDAP Entry.
 */
class Entry
{
    /**
     * LDAP connection resource.
     *
     * @var resource
     */
    protected $ds;

    /**
     * Relative distinguished name (to baseDN).
     *
     * @var string
     */
    public $rdn;

    /**
     * Distinguished name.
     *
     * @var string
     */
    public $dn;

    /**
     * Attribute name of DN.
     *
     * @var string
     */
    public $dnAttribute;

    /**
     * Associative array of attribute keys and values.
     *
     * @var array
     */
    public $data;

    /**
     * Data of LDAP entry before changes.
     *
     * @var array
     */
    protected $oldData;

    /**
     * Entry constructor.
     *
     * @param resource $ds
     *   LDAP connection resource.
     * @param string $rdn
     *   Relative distinguished name (to baseDN).
     * @param string $dn
     *   Distinguished name.
     * @param array $data
     *   Associative array of attribute keys and values.
     */
    public function __construct($ds, $rdn, $dn, $data)
    {
        $this->ds = $ds;
        $this->rdn = $rdn;
        $this->dn = $dn;
        $this->data = $data;
        $this->oldData = $data;
        $exploded_dn = ldap_explode_dn($dn, 0);
        $top_dn = explode('=', $exploded_dn[0]);
        $this->dnAttribute = strtolower($top_dn[0]);
    }

    /**
     * Check for LDAP errors.
     *
     * @throws Exception
     */
    protected function checkForError()
    {
        Exception::checkForLdapError($this->ds);
    }

    /**
     * Delete attribute from entry.
     *
     * @param string $attributeName
     *   Name of attribute to delete.
     */
    public function deleteAttribute($attributeName)
    {
        @ldap_mod_del($this->ds, $this->dn, array($attributeName => array()));
        $this->checkForError();
        unset($this->oldData[$attributeName]);
        unset($this->data[$attributeName]);
    }

    /**
     * Update entry on LDAP server.
     */
    public function update()
    {
        $add = array();
        $replace = array();
        $delete = array();
        $renameTo = null;
        foreach ($this->data as $key => $val) {
            if ($key == $this->dnAttribute && $val !== $this->oldData[$key]) {
                $renameTo = $val;
            } elseif (array_key_exists($key, $this->oldData)) {
                if ($val == null) {
                    $delete[$key] = array();
                } elseif ($val !== $this->oldData[$key]) {
                    $replace[$key] = $val;
                }
            } elseif ($val != null) {
                $add[$key] = $val;
            }
        }
        if (count($add) > 0) {
            @ldap_mod_add($this->ds, $this->dn, $add);
            $this->checkForError();
        }
        if (count($replace) > 0) {
            @ldap_mod_replace($this->ds, $this->dn, $replace);
            $this->checkForError();
        }
        if (count($delete) > 0) {
            @ldap_mod_del($this->ds, $this->dn, $delete);
            $this->checkForError();
        }
        if ($renameTo) {
            $topRDN = $this->dnAttribute . '=' . $renameTo;
            $parent = Utils::getParent($this->dn);
            @ldap_rename($this->ds, $this->dn, $topRDN, $parent, true);
            $this->checkForError();
            $this->rdn = $topRDN . ',' . Utils::getParent($this->rdn);
            $this->dn = $topRDN . ',' . $parent;
        }
    }
}
