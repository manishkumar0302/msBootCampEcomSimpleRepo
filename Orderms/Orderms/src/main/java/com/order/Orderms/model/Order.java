package com.order.Orderms.model;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.persistence.UniqueConstraint;

@Entity
@Table(	name = "orders", 
		uniqueConstraints = { 
			@UniqueConstraint(columnNames = "ordernb")
		})
public class Order {

	@Id
	@GeneratedValue(strategy = GenerationType.AUTO)
	private int ordernb;
	private String orderDesc;
	private String quantity;
	private String transToken;
	
	public Order() {
		
	}
	
	public Order(String orderDesc, String quantity, String transToken) {
		super();
		this.orderDesc = orderDesc;
		this.quantity = quantity;
		this.transToken = transToken;
	}

	public String getOrderDesc() {
		return orderDesc;
	}
	
	public void setOrderDesc(String orderDesc) {
		this.orderDesc = orderDesc;
	}
	public String getQuantity() {
		return quantity;
	}
	public void setQuantity(String quantity) {
		this.quantity = quantity;
	}
	

	@Override
	public String toString() {
		return "Order [ordernb=" + ordernb + ", orderDesc=" + orderDesc + ", quantity=" + quantity + ", transToken="
				+ transToken + "]";
	}

	public String getTransToken() {
		return transToken;
	}

	public void setTransToken(String transToken) {
		this.transToken = transToken;
	}
	
}
