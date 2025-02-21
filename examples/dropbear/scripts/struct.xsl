<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
  <xsl:param name="protocol" />
  <xsl:template match="/">
    <structs>
    <xsl:for-each select="//proto[@name=$protocol]">
      <xsl:call-template name="proto">
	<xsl:with-param name="offset" select="@pos" />
	<xsl:with-param name="index" select="position()" />
	<xsl:with-param name="size" select="@size" />
      </xsl:call-template>
    </xsl:for-each>
    </structs>
</xsl:template>

<xsl:template name="proto">
  <xsl:param name="offset" />
  <xsl:param name="index" />
  <xsl:param name="size" />
  <struct name="{concat('packet',$index)}" size="{$size}">
    <xsl:for-each select=".//field[count(./*)=0 and @size!='0']">
      <field name="{@name}" size="{@size}" offset="{number(@pos)-number($offset)}" value="{@value}" />
    </xsl:for-each>
  </struct>
</xsl:template>
</xsl:stylesheet>
