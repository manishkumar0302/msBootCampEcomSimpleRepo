package com.order.Orderms.Repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.order.Orderms.model.Order;

public interface OrderRepository extends JpaRepository<Order, Integer> {

}
