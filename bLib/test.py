from abc import ABC, abstractmethod

class Parent(ABC):
	def __init__(self):
		print ('init')

	@abstractmethod
	def a(self):
		pass

class Child(Parent):
	def __init__(self):
		pass
		
	def a(self):
		pass


A = Child()
A.a()