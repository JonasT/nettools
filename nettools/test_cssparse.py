
'''
nettools - Copyright 2019 python nettools team, see AUTHORS.md

This software is provided 'as-is', without any express or implied
warranty. In no event will the authors be held liable for any damages
arising from the use of this software.

Permission is granted to anyone to use this software for any purpose,
including commercial applications, and to alter it and redistribute it
freely, subject to the following restrictions:

1. The origin of this software must not be misrepresented; you must not
   claim that you wrote the original software. If you use this software
   in a product, an acknowledgment in the product documentation would be
   appreciated but is not required.
2. Altered source versions must be plainly marked as such, and must not be
   misrepresented as being the original software.
3. This notice may not be removed or altered from any source distribution.
'''

import os
import sys
sys.path = [os.path.abspath(os.path.join(
                            os.path.dirname(__file__), ".."))] + sys.path

import nettools.cssparse as cssparse


def test_extract_string_without_comments():
    result = cssparse.extract_string_without_comments(
        "abc /*def*/ flu {value:'/*test'}"
    )
    assert(result == "abc  flu {value:'/*test'}")
    result = cssparse.extract_string_without_comments(
        "/* \"abc \" def\\\" */\"ab\\\"/*\""
    )
    assert(result == "\"ab\\\"/*\"")


def test_extract_rule_strings():
    result = cssparse.extract_rule_strings(
        "myrule{a:1}/*test } a */myrule2{b:2}"
    )
    assert(len(result) == 2)
    assert(result[0] == "myrule{a:1}")
    assert(result[1] == "myrule2{b:2}")


def test_attribute_priorities():
    result = cssparse.parse("""
        * {border-style:solid;}
        body {border:1px solid red;border-width:2px;}
    """)
    result = result.get_item_attributes(
        "body", nondirectional_can_override_directional=True
    )
    attributes = result.attributes
    attribute_priorities = result.priorities
    assert(set(attributes.keys()) == {
        "border", "border-style", "border-width"
    })
    assert(attribute_priorities["border"] ==
           attribute_priorities["border-width"])
    assert(attribute_priorities["border-style"] <
           attribute_priorities["border"])
    assert(attribute_priorities["border-style"] <
           attribute_priorities["border-width"])


def test_parse():
    result = cssparse.parse("""
        * {padding:5px}
        body {height:15px; padding:10px;}
    """)

    assert(len(result.rules) == 2)
    assert(result.rules[0].selector.items == ["*"])
    assert(len(result.rules[0].attributes) == 1)
    assert(result.rules[1].selector.items == ["body"])
    assert(len(result.rules[1].attributes) == 2)


def test_cssselector_check_item():
    cssparse.enable_selector_debugging()

    assert(cssparse.CSSSelector.check_item(
        "*", "bla"
    ) is True)
    assert(cssparse.CSSSelector.check_item(
        ".test", "bla"
    ) is False)
    assert(cssparse.CSSSelector.check_item(
        ".test", "bla", item_classes=["test"]
    ) is True)
    assert(cssparse.CSSSelector.check_item(
        ".test.test2", "bla", item_classes=["test"]
    ) is False)
    assert(cssparse.CSSSelector.check_item(
        ".test", "bla", item_classes=["test2", "test"]
    ) is True)
    assert(cssparse.CSSSelector.check_item(
        "myitem.test1.test2", "myitem",
        item_classes=["test1", "test2", "test3"]
    ) is True)


def test_complex_selector_scenarios():
    cssparse.enable_selector_debugging()

    result = cssparse.parse("""
        * {padding:5px}
        body {height:15px; padding:10px;}
    """)
    attributes = result.get_item_attributes("body").attributes
    assert(set(attributes.keys()) == {"height", "padding"})
    assert(attributes["height"].value == "15px")

    result = cssparse.parse("""
        body {height:15px; padding:10px;}
        * {padding:5px}
    """)
    attributes = result.get_item_attributes("body").attributes
    assert(set(attributes.keys()) == {"height", "padding"})
    assert(attributes["height"].value == "15px")
    assert(attributes["padding"].value == "10px")

    result = cssparse.parse("""
        body {height:15px; padding:10px;}
        body {padding:5px}
    """)
    attributes = result.get_item_attributes("body").attributes
    assert(set(attributes.keys()) == {"height", "padding"})
    assert(attributes["height"].value == "15px")
    assert(attributes["padding"].value == "5px")


def test_directional_fallback_to_nondirectional():
    cssparse.enable_selector_debugging()

    result = cssparse.parse("""
        * {padding-left:5px}
        body {padding:10px;}
    """)
    attributes = result.get_item_attributes(
        "body", nondirectional_can_override_directional=True
    ).attributes
    assert("padding" in attributes)
    if "padding-left" in attributes:
        assert(attributes["padding-left"].value == "10px")
    else:
        assert(attributes["padding"].value == "10px")

    print("*****************")
    result = cssparse.parse("""
        * {padding-left:5px}
        body {padding:10px;padding-left:3px;}
    """)
    attributes = result.get_item_attributes(
        "body", nondirectional_can_override_directional=True
    ).attributes
    assert(set(attributes.keys()) == {"padding", "padding-left"})
    assert(attributes["padding-left"].value == "3px")

    result = cssparse.parse("""
        * {padding-left:5px}
        body {padding:10px;}
    """)
    attributes = result.get_item_attributes(
        "body", nondirectional_can_override_directional=False
    ).attributes
    assert(attributes["padding-left"].value == "5px")
