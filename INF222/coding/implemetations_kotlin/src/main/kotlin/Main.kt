package org.example

import src.main.kotlin.Generics
import src.main.kotlin.Varience
import src.main.kotlin.Varience_in

fun main() {
    var int_holder : Generics<Int> = Generics<Int>(10);
    var str_holder: Generics<String> = Generics<String>("hello")
    var a = int_holder.get_thing()
    var b = str_holder.get_thing()

    var arr: Array<Int> = arrayOf(1,2,3,4)
    Generics.getFirst(arr)
    var c: Double = Generics.add_generics(1,2.5)

    var q: Varience<Number> = Varience<Number>(1)
    var w: Varience<Int> = Varience<Int>(19)
    q = w
    //this will work since we use the out keyword

    val any_printer: Varience_in<Any>
    var string_printer = Varience_in<Any>()
    any_printer = string_printer
    string_printer.print_value("allo")


}
