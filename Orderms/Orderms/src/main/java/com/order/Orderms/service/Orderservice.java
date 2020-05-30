package com.order.Orderms.service;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.order.Orderms.Repository.OrderRepository;
import com.order.Orderms.model.Order;

@Service
public class Orderservice {
	
	@Autowired
	private OrderRepository repo;
	
		
	public String processOrder(Order ord) {
		
		repo.save(ord);
		return null;
	}
	
	
}


