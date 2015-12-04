<?php
namespace Ldap;

/**
 * LDAP search results.
 */
class SearchResults
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
     * LDAP search result resource.
     *
     * @var resource
     */
    protected $sr;

    /**
     * Names of binary attributes.
     *
     * @var string[]
     */
    protected $binaryFields;

    /**
     * LDAP entry resource.
     *
     * @var resource
     */
    protected $entryID = null;

    /**
     * LDAP search results.
     *
     * @param resource $ds
     *   LDAP connection resource.
     * @param string $baseDN
     *   Base distinguished name.
     * @param resource $sr
     *   LDAP search result resource.
     * @param string[] $binaryFields
     *   Names of binary attributes.
     */
    public function __construct($ds, $baseDN, $sr, $binaryFields)
    {
        $this->ds = $ds;
        $this->baseDN = $baseDN;
        $this->sr = $sr;
        $this->binaryFields = $binaryFields;
    }

    /**
     * Get the next LDAP entry from search results.
     *
     * @return Entry|null
     *   Next LDAP entry or null if no entries left.
     */
    public function next()
    {
        if ($this->entryID === null) {
            $this->entryID = ldap_first_entry($this->ds, $this->sr);
        } else {
            $this->entryID = ldap_next_entry($this->ds, $this->entryID);
        }
        if (!$this->entryID) {
            return null;
        }
        $data = Utils::readEntry($this->ds, $this->entryID, $this->binaryFields);
        if (array_key_exists('nsRole', $data)) {
            $data['roles'] = Utils::getRoles($this->ds, $data);
        }
        $dn = ldap_get_dn($this->ds, $this->entryID);
        $rdn = Utils::getRDN($dn, $this->baseDN);
        return new Entry($this->ds, $rdn, $dn, $data);
    }

    /**
     * Get the number of LDAP entries.
     *
     * @return int
     *   Number of LDAP entries.
     */
    public function count()
    {
        return ldap_count_entries($this->ds, $this->sr);
    }

    /**
     * Sort search results by attribute.
     *
     * @param string $sortBy
     *   Name of LDAP attribute to sort by.
     */
    public function sort($sortBy)
    {
        if (is_array($sortBy)) {
            $sortAttributes = array_reverse($sortBy);
            foreach ($sortAttributes as $sortAttr) {
                ldap_sort($this->ds, $this->sr, $sortAttr);
            }
        } else {
            ldap_sort($this->ds, $this->sr, $sortBy);
        }
    }

    /**
     * Get all LDAP entries.
     *
     * @param bool $dataOnly
     *   (Optional) If true only include attribute data for the entry.
     * @param bool $includeDN
     *   (Optional) Flag to include RDN and DN in the entries. Defaults to true.
     *
     * @return Entry[]|array
     *   LDAP entries.
     */
    public function getAll($dataOnly = false, $includeDN = true)
    {
        $results = array();
        while ($entry = $this->next()) {
            if ($dataOnly) {
                if ($includeDN) {
                    $results[] = array_merge(array('rdn' => $entry->rdn, 'dn' => $entry->dn), $entry->data);
                } else {
                    $results[] = $entry->data;
                }
            } else {
                $results[] = $entry;
            }
        }
        return $results;
    }

    /**
     * Get attribute column from search results.
     *
     * @param string $columnName
     *   (Optional) Attribute name.
     *
     * @return array
     *   Attribute values for column.
     */
    public function getCol($columnName = null)
    {
        $results = array();
        while ($entry = $this->next()) {
            if ($columnName == null) {
                $columnName = key($entry->data);
            }
            $results[] = $entry->data[$columnName];
        }
        return $results;
    }

    /**
     * Get associative array from pair of columns from search results.
     *
     * @param string $idColumnName
     *   (Optional) Attribute name of key column.
     * @param string $valueColumnName
     *   (Optional) Attribute name of value column.
     *
     * @return array
     *   Associative array of $idColumnName value and its associated $valueColumnName value.
     */
    public function getAssoc($idColumnName = null, $valueColumnName = null)
    {
        $results = array();
        while ($entry = $this->next()) {
            if ($idColumnName == null) {
                $idColumnName = key($entry->data);
            }
            if ($valueColumnName == null) {
                $keys = array_keys($entry->data);
                $valueColumnName = $keys[1];
            }
            $results[$entry->data[$idColumnName]] = $entry->data[$valueColumnName];
        }
        return $results;
    }
}
