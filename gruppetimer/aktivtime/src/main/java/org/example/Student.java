package org.example;

public class Student {
	String navn;
	static int antallStudenter;

	Student(String navn) {
		this.navn = navn;
		antallStudenter++;
	}

	public static void main(String[] args) {
		Student s1 = new Student("Bob");
		Student s2 = new Student("Bob");

		System.out.println(s1.antallStudenter);
		System.out.println(s2.antallStudenter);
	}
}
