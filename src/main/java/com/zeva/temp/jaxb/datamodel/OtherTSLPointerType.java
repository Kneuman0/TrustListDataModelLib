//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2017.02.16 at 11:23:28 AM EST 
//


package com.zeva.temp.jaxb.datamodel;

import javafx.beans.property.SimpleObjectProperty;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlTransient;
import javax.xml.bind.annotation.XmlType;

import com.zeva.tlgen.dataModel.TLPointer;


/**
 * <p>Java class for OtherTSLPointerType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="OtherTSLPointerType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element ref="{http://uri.etsi.org/02231/v2#}ServiceDigitalIdentities" minOccurs="0"/>
 *         &lt;element name="TSLLocation" type="{http://uri.etsi.org/02231/v2#}NonEmptyURIType"/>
 *         &lt;element ref="{http://uri.etsi.org/02231/v2#}AdditionalInformation" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "OtherTSLPointerType", propOrder = {
    "serviceDigitalIdentities",
    "tslLocation",
    "additionalInformation"
})
public class OtherTSLPointerType extends TLPointer {

    @XmlElement(name = "ServiceDigitalIdentities")
    protected ServiceDigitalIdentityListType serviceDigitalIdentities;
    @XmlElement(name = "TSLLocation", required = true)
    @XmlSchemaType(name = "anyURI")
    protected String tslLocation;
    @XmlElement(name = "AdditionalInformation")
    protected AdditionalInformationType additionalInformation;
    
    @XmlTransient
    private SimpleObjectProperty<TLPointer> name;
    @XmlTransient
    private String stringName;
    @XmlTransient
    private String schemeOperatorName;
    @XmlTransient
    private String TSLType;
    
    public OtherTSLPointerType(){
    	this.name = new SimpleObjectProperty<TLPointer>(this);
    }
    
    public OtherTSLPointerType(String name){
    	this.stringName = name;
    }

    /**
     * Gets the value of the serviceDigitalIdentities property.
     * 
     * @return
     *     possible object is
     *     {@link ServiceDigitalIdentityListType }
     *     
     */
    public ServiceDigitalIdentityListType getServiceDigitalIdentities() {
        return serviceDigitalIdentities;
    }

    /**
     * Sets the value of the serviceDigitalIdentities property.
     * 
     * @param value
     *     allowed object is
     *     {@link ServiceDigitalIdentityListType }
     *     
     */
    public void setServiceDigitalIdentities(ServiceDigitalIdentityListType value) {
        this.serviceDigitalIdentities = value;
    }

    /**
     * Gets the value of the tslLocation property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getTSLLocation() {
        return tslLocation;
    }

    /**
     * Sets the value of the tslLocation property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setTSLLocation(String value) {
        this.tslLocation = value;
    }
    
    

    public String getSchemeOperatorName() {
		return schemeOperatorName;
	}

	public void setSchemeOperatorName(String schemeOperatorName) {
		this.schemeOperatorName = schemeOperatorName;
	}

	public String getTSLType() {
		return TSLType;
	}

	public void setTSLType(String tSLType) {
		TSLType = tSLType;
	}

	/**
     * Gets the value of the additionalInformation property.
     * 
     * @return
     *     possible object is
     *     {@link AdditionalInformationType }
     *     
     */
    public AdditionalInformationType getAdditionalInformation() {
        return additionalInformation;
    }

    /**
     * Sets the value of the additionalInformation property.
     * 
     * @param value
     *     allowed object is
     *     {@link AdditionalInformationType }
     *     
     */
    public void setAdditionalInformation(AdditionalInformationType value) {
        this.additionalInformation = value;
    }
    
    @Override
    public String toString(){
    	StringBuilder builder = new StringBuilder();
    	builder.append("Published By: " + schemeOperatorName + "\n");
    	builder.append("Location: " + tslLocation + "\n");
    	builder.append("Trust List Type: " + TSLType);
    	
    	return builder.toString();
    }

	@Override
	public SimpleObjectProperty<TLPointer> nameProperty() {
		// TODO Auto-generated method stub
		return name;
	}

	@SuppressWarnings("unchecked")
	@Override
	public OtherTSLPointerType getEncapsulatedBean() {
		// TODO Auto-generated method stub
		return this;
	}

	@Override
	public String getStringName() {
		// TODO Auto-generated method stub
		return stringName;
	}

	@Override
	public TLPointer initialize() {
		this.name = new SimpleObjectProperty<TLPointer>(this);
		return this;
	}


}
