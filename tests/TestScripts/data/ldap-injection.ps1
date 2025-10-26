# Test script for LDAPInjection rule
# This script contains intentional security violations for testing purposes

# ❌ VIOLATION: Direct string concatenation in LDAP filter
$username = Read-Host "Enter username"
$filter = "(&(objectClass=user)(sAMAccountName=$username))"
Get-ADUser -LDAPFilter $filter

# ❌ VIOLATION: Building LDAP query with user input
$groupName = $args[0]
$ldapQuery = "(memberOf=CN=$groupName,OU=Groups,DC=company,DC=com)"
Get-ADUser -LDAPFilter $ldapQuery

# ❌ VIOLATION: Unsafe LDAP filter construction
$searchTerm = $env:SEARCH_USER
$filterString = "(&(objectClass=person)(cn=*$searchTerm*))"
$searcher = [adsisearcher]$filterString
$searcher.FindAll()

# ❌ VIOLATION: DirectorySearcher with unvalidated input
$dept = Read-Host "Department"
$ds = New-Object System.DirectoryServices.DirectorySearcher
$ds.Filter = "(&(objectClass=user)(department=$dept))"
$ds.FindAll()

# ✅ SAFE: Using proper AD cmdlets with safer methods (should not be flagged)
$safeUser = Read-Host "Enter username"
# This is still somewhat simplified, but using Identity parameter is safer
Get-ADUser -Identity $safeUser
