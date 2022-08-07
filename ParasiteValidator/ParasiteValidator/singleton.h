#pragma once

template <class T> 
class Singleton {
protected:
	Singleton() {}

public:
	virtual ~Singleton() {}

	// Copy
	Singleton(const Singleton<T>&) = delete;
	Singleton<T> operator=(const Singleton<T>&) = delete;
	
	inline static T* getInstance()
	{
		static T instance{};
		return &instance;
	}
};
