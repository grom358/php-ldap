<?php
namespace Ldap;

/**
 * LDAP Connection.
 */
class Connection
{
    /**
     * LDAP connection resource.
     *
     * @var resource
     */
    protected $ds;

    /**
     * Base distinguished name.
     *
     * @var string
     */
    protected $baseDN;

    /**
     * Hostname of LDAP server.
     *
     * @var string
     */
    protected $hostname;

    /**
     * Port of LDAP server.
     *
     * @var int
     */
    protected $port;

    /**
     * List of binary fields for LDAP entry.
     *
     * @var string[]
     */
    protected $binaryFields;

    /**
     * Is connected status.
     *
     * @var bool
     */
    private $isConnected;

    /**
     * Create LDAP connection.
     *
     * @param array $config
     *   Connection configuration.
     *
     * @throws Exception
     */
    public function __construct(array $config)
    {
        if (!isset($config['hostname'])) {
            throw new Exception("Hostname not specified.");
        }
        if (empty($config['baseDN'])) {
            throw new Exception("baseDN not specified.");
        }

        $this->hostname = $config['hostname'];
        if (strlen($this->hostname) > 8 && substr($this->hostname, 0, 8) == 'ldaps://') {
            $defaultPort = 636;
        } else {
            $defaultPort = 389;
        }
        $this->port = isset($config['port']) ? $config['port'] : $defaultPort;
        $this->ds = ldap_connect($this->hostname, $this->port);
        if (!$this->ds) {
            // Connections to fedora directory don't fail till binding.
            $this->ds = null;
            throw new Exception("Could not connect to " . $this->hostname . ':' . $this->port, -1);
        }
        $this->setDefaultOptions();
        // Bind as anonymous to test connection.
        if (!@ldap_bind($this->ds)) {
            $this->ds = null;
            throw new Exception("Could not connect to " . $this->hostname . ':' . $this->port, -1);
        }
        $this->baseDN = $config['baseDN'];
        $this->binaryFields = isset($config['binaryFields']) ? $config['binaryFields'] : array();
        $this->isConnected = true;
    }

    /**
     * Set default connection options.
     */
    protected function setDefaultOptions()
    {
        ldap_set_option($this->ds, LDAP_OPT_PROTOCOL_VERSION, 3);
    }

    /**
     * Disconnect.
     */
    public function __destruct()
    {
        $this->disconnect();
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
     * Bind.
     *
     * @param string $dn
     * @param string $password
     *
     * @throws Exception
     */
    public function bind($dn, $password)
    {
        if (!@ldap_bind($this->ds, $dn, $password)) {
            $errorCode = ldap_errno($this->ds);
            if ($errorCode == 32) {
                throw new Exception("Unable to bind as " . $dn, $errorCode);
            } elseif ($errorCode == -1) {
                // It appears a connection to fedora directory doesn't occur till you attempt to bind
                throw new Exception("Could not connect to " . $this->hostname . ':' . $this->port, $errorCode);
            } else {
                $this->checkForError();
            }
        }
    }

    /**
     * Search.
     *
     * @param string|Filter $filter
     *   Search filter.
     * @param array $attributes
     *   An array of the required attributes.
     * @param string $searchRDN
     *   (Optional) Relative DN to search. Defaults to baseDN of connection.
     *
     * @return SearchResults
     */
    public function search($filter, $attributes = array(), $searchRDN = null)
    {
        $filter = (string) $filter;
        $searchDN = $this->baseDN;
        if ($searchRDN) {
            $searchDN = $searchRDN . ',' . $this->baseDN;
        }
        $sr = @ldap_search($this->ds, $searchDN, $filter, $attributes);
        $this->checkForError();
        return new SearchResults($this->ds, $this->baseDN, $sr, $this->binaryFields);
    }

    /**
     * Read LDAP entry.
     *
     * @param string $rdn
     *   Relative distinguished name of LDAP entry.
     * @param string[] $attributes.
     *   Required attributes.
     *
     * @return Entry
     *   Returns the LDAP entry or null if no record found.
     */
    public function read($rdn, $attributes = array())
    {
        $dn = $rdn . ',' . $this->baseDN;
        $data = Utils::getEntry($this->ds, $dn, $attributes, $this->binaryFields);
        if ($data == null) {
            return null;
        }
        if (array_key_exists('nsRole', $data)) {
            $data['roles'] = Utils::getRoles($this->ds, $data);
        }
        return new Entry($this->ds, $rdn, $dn, $data);
    }

    /**
     * Add LDAP entry.
     *
     * @param string $rdn
     *   The distinguished name of an LDAP entry relative to baseDN.
     * @param array $data
     *   An array that specifies the information about the entry. The values in
     *   the entries are indexed by individual attributes.
     *   In case of multiple values for an attribute, they are indexed using
     *   integers starting with 0.
     */
    public function add($rdn, $data)
    {
        $dn = $rdn . ',' . $this->baseDN;
        @ldap_add($this->ds, $dn, $data);
        $this->checkForError();
    }

    /**
     * Delete LDAP entry.
     *
     * @param string $rdn
     *   The distinguished name of an LDAP entry relative to baseDN.
     */
    public function delete($rdn)
    {
        $dn = $rdn . ',' . $this->baseDN;
        @ldap_delete($this->ds, $dn);
        $this->checkForError();
    }

    /**
     * Modify the name of an LDAP entry.
     *
     * @param string $oldRDN
     *   The old RDN.
     * @param string $newRDN
     *   The new RDN.
     * @param string $newParent
     *   The new parent.
     * @param bool $deleteOldDN
     *   If TRUE the old RDN value(s) is removed, else the old RDN value(s)
     *   is retained as non-distinguished values of the entry.
     */
    public function rename($oldRDN, $newRDN, $newParent = null, $deleteOldDN = false)
    {
        $oldDN = $oldRDN . ',' . $this->baseDN;
        if ($newParent == null) {
            $newParent = Utils::getParent($oldDN);
        } else {
            $newParent .= ',' . $this->baseDN;
        }
        @ldap_rename($this->ds, $oldDN, $newRDN, $newParent, $deleteOldDN);
        $this->checkForError();
    }

    /**
     * Move an LDAP entry.
     *
     * @param string $oldRDN
     *   The old RDN.
     * @param string $newRDN
     *   The new RDN.
     */
    public function move($oldRDN, $newRDN)
    {
        $oldDN = $oldRDN . ',' . $this->baseDN;
        $newDN = $newRDN . ',' . $this->baseDN;
        $parent = Utils::getParent($oldDN);
        $topRDN = Utils::getRDN($newDN, $parent);
        @ldap_rename($this->ds, $oldDN, $topRDN, $parent, false);
        $this->checkForError();
    }

    /**
     * Shortcut for adding attributes.
     *
     * @param string $rdn
     *   Relative distinguished name.
     * @param array $data
     *   Attribute keys/values to add.
     */
    public function addAttributes($rdn, $data)
    {
        $dn = $rdn . ',' . $this->baseDN;
        @ldap_mod_add($this->ds, $dn, $data);
        $this->checkForError();
    }

    /**
     * Shortcut for replacing attributes.
     *
     * @param string $rdn
     *   Relative distinguished name.
     * @param array $data
     *   Attribute keys/values to replace.
     */
    public function replaceAttributes($rdn, $data)
    {
        $dn = $rdn . ',' . $this->baseDN;
        @ldap_mod_replace($this->ds, $dn, $data);
        $this->checkForError();
    }

    /**
     * Shortcut for deleting attributes.
     *
     * @param string $rdn
     *   Relative distinguished name.
     * @param array $data
     *   Attribute keys/values to delete.
     */
    public function deleteAttributes($rdn, $data)
    {
        $dn = $rdn . ',' . $this->baseDN;
        @ldap_mod_del($this->ds, $dn, $data);
        $this->checkForError();
    }

    /**
     * Disconnect.
     */
    public function disconnect()
    {
        if ($this->isConnected) {
            ldap_close($this->ds);
        }
        $this->isConnected = false;
    }
}
