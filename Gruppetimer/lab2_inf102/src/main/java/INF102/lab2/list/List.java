package INF102.lab2.list;

public interface List<T> {
	
	/**
     * Returns the number of elements in this list.
     *
     * @return the number of elements in this list
     */
	public int size();
	
	/**
     * Returns {@code true} if this list contains no elements.
     *
     * @return {@code true} if this list contains no elements
     */
	public boolean isEmpty();
	
	 /**
     * Returns the element at the specified position in this list.
     *
     * @param index index of the element to return
     * @return the element at the specified position in this list
     * @throws IndexOutOfBoundsException if the index is out of range
     *         ({@code index < 0 || index >= size()})
     */
	public T get(int index);
	
	/**
     * Inserts the specified element at the specified position in this list.
     * Shifts the element currently at that position (if any) and any
     * subsequent elements to the right (adds one to their indices).
     *
     * @param index index at which the specified element is to be inserted
     * @param element element to be inserted
     * @throws IndexOutOfBoundsException if the index is out of range
     *         ({@code index < 0 || index > size()})
     */
	public void add(int index, T element);
	
	/**
     * Appends the specified element to the beginning of this list.
     *
     * @param element element to be appended to this list
     */
	default void addFirst(T element) {
		add(0, element);
	};

	/**
     * Appends the specified element to the end of this list.
     *
     * @param element element to be appended to this list
     */
	default void addLast(T element) {
		add(size(), element);
	};
}