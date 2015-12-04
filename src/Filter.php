<?php
namespace Ldap;

/**
 * LDAP search filter.
 */
class Filter
{
    /**
     * @var string
     */
    private $filter;

    /**
     * Create Filter from filter string.
     *
     * @param string $filter
     *   LDAP search filter.
     *
     * @return Filter
     *   LDAP search filter.
     */
    static public function create($filter = 'objectclass=*')
    {
        $builder = new Filter('(' . $filter . ')');
        return $builder;
    }

    /**
     * Filter constructor.
     *
     * @param string $filter
     *   Search filter.
     */
    private function __construct($filter)
    {
        $this->filter = $filter;
    }

    /**
     * And combine with another filter.
     *
     * @param string|Filter $filter
     *   Filter to combine with.
     *
     * @return Filter
     *   Combined filter.
     */
    public function and_($filter)
    {
        if ($filter instanceof Filter) {
            $filter = '(&' . $this->filter . $filter->filter . ')';
        } else {
            $filter = '(&' . $this->filter . '(' . $filter . '))';
        }
        return new Filter($filter);
    }

    /**
     * Or combine with another filter.
     *
     * @param string|Filter $filter
     *   Filter to combine with.
     *
     * @return Filter
     *   Combined filter.
     */
    public function or_($filter)
    {
        if ($filter instanceof Filter) {
            $filter = '(|' . $this->filter . $filter->filter . ')';
        } else {
            $filter = '(|' . $this->filter . '(' . $filter . '))';
        }
        return new Filter($filter);
    }

    /**
     * Apply not operation to filter.
     *
     * @param string $filter
     *   Filter to not
     *
     * @return string
     *   Not filter.
     */
    static private function _not($filter)
    {
        if ($filter instanceof Filter) {
            return '!' . $filter->filter;
        } else {
            return '!(' . $filter . ')';
        }
    }

    /**
     * Not filter.
     *
     * @param string|Filter $filter
     *   Search filter.
     *
     * @return Filter
     *   Not filter.
     */
    static public function not($filter)
    {
        return new Filter('(' . self::_not($filter) . ')');
    }

    /**
     * andNot filter.
     *
     * @param string|Filter $filter
     *   Search filter.
     *
     * @return Filter
     *   Combined filter.
     */
    public function andNot($filter)
    {
        return $this->and_(self::_not($filter));
    }

    /**
     * orNot filter.
     *
     * @param string|Filter $filter
     *   Search filter.
     *
     * @return Filter
     *   Combined filter.
     */
    public function orNot($filter)
    {
        return $this->or_(self::_not($filter));
    }

    public function __toString()
    {
        return $this->filter;
    }
}
