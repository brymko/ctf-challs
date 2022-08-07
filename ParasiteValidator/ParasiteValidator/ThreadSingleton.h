#pragma once

template <class T>
class ThreadSingleton {
protected:
	ThreadSingleton() {}

public:
	virtual ~ThreadSingleton() {}

	// Copy
	ThreadSingleton(const ThreadSingleton<T>&) = delete;
	ThreadSingleton<T> operator=(const ThreadSingleton<T>&) = delete;
	
	inline static T* getInstance()
	{
		thread_local static T instance;
		return &instance;
	}
};
