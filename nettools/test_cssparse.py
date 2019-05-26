
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


def test_none_as_color():
    result = cssparse.parse("""
        * {background-color:red;}
    """)
    assert(result.get_item_attributes("body").
           attributes["background-color"].value == 'red')
    result = cssparse.parse("""
        * {background-color:red;}
        body {background-color:none;}
    """)
    assert("background-color" not in \
           result.get_item_attributes(
               "body", clear_out_none_values=True
           ).attributes)


def test_multitag_query():
    ruleset = cssparse.parse("""
        * {background-color:blue;}
        html {color:yellow;}
        body {background-color:red;}
    """)
    result = ruleset.get_item_attributes(
        ["html", "body"],
    )
    assert(result.attributes["color"].value == "yellow")
    assert(result.attributes["background-color"].value == "red")


def test_extract_rule_strings():
    result = cssparse.extract_rule_strings(
        "myrule{a:1}/*test } a */myrule2{b:2}"
    )
    assert(len(result) == 2)
    assert(result[0] == "myrule{a:1}")
    assert(result[1] == "myrule2{b:2}")


def test_child_and_descendant_selectors():
    cssparse.enable_selector_debugging()

    result = cssparse.parse("""
        div span {color:red;}
    """)
    result = result.get_item_attributes(
        "span", get_next_parent_info=[
            ("p",),
            ("div",),
        ]
    )
    assert(result.attributes["color"].value == "red")
    result = cssparse.parse("""
        div > span {color:red;}
    """)
    result = result.get_item_attributes(
        "span", get_next_parent_info=[
            ("p",),
            ("div",),
        ]
    )
    assert("color" not in result.attributes)


def test_css_selector_item_constructor():
    item = cssparse.CSSSelectorItem("#test")
    assert(len(item.colon_special_constraints) == 0)
    assert(item.check_against(["foobar"], element_id="test"))
    assert(not item.check_against(["foobar"]))
    assert(not item.check_against(["foobar"], element_id="foobar"))
    item = cssparse.CSSSelectorItem("#test:last-child")
    assert(len(item.colon_special_constraints) == 1)
    assert(not item.check_against(["whatever"],
        element_id="test",
        get_following_sibling_info=iter([("div",), ("p",)]).__next__,
    ))
    assert(item.check_against(["whatever"],
        element_id="test",
        get_following_sibling_info=iter([]).__next__,
    ))


def test_csstransform_parse_border():
    result = cssparse.parse("""
        * {border-style:dotted;}
        body {border:1px solid red;border-width:2px;}
    """)
    result = result.get_item_attributes(
        "body", nondirectional_can_override_directional=True,
        transform_funcs=[cssparse.csstransform_parse_border],
    )
    attributes = result.attributes
    assert(set(attributes.keys()) == {
        "border-width", "border-style", "border-color"
    })
    assert(attributes["border-width"].value == "2px")
    assert(attributes["border-style"].value == "solid")
    assert(attributes["border-color"].value == "#ff0000")

    # Retry with different rule order, and one more override:
    result = cssparse.parse("""
        body {border-width:2px;border:1px solid red;}
        * {border-style:dotted; border-width:5px;}
    """)
    result = result.get_item_attributes(
        "body", nondirectional_can_override_directional=True,
        transform_funcs=[cssparse.csstransform_parse_border],
    )
    attributes = result.attributes
    assert(set(attributes.keys()) == {
        "border-width", "border-style", "border-color"
    })
    assert(attributes["border-width"].value == "2px")
    assert(attributes["border-style"].value == "solid")
    assert(attributes["border-color"].value == "#ff0000")


def test_attribute_priorities():
    result = cssparse.parse("""
        * {border-style:solid;}
        body {border:1px solid red;border-width:2px;}
    """)
    result = result.get_item_attributes(
        "body", nondirectional_can_override_directional=True,
        transform_funcs=[],
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


def test_parse_border_attribute():
    (border_type, border_color, border_width) = \
        cssparse.parse_border_attribute(
            "1px", be_lenient_with_incomplete=False,
        )
    assert(border_type is None and
           border_color is None and
           border_width == "1px")
    (border_type, border_color, border_width) = \
        cssparse.parse_border_attribute(
            "1px solid", be_lenient_with_incomplete=False,
        )
    assert(border_type == "solid" and
           border_color is None and
           border_width == "1px")
    (border_type, border_color, border_width) = \
        cssparse.parse_border_attribute(
            "solid 2px green", be_lenient_with_incomplete=False,
        )
    assert(border_type == "solid" and
           border_color == "#00ff00" and
           border_width == "2px")


def test_parse():
    result = cssparse.parse("""
        * {padding:5px}
        body {height:15px; padding:10px;}
    """)

    assert(len(result.rules) == 2)
    assert(result.rules[0].selector.as_str_list() == ["*"])
    assert(len(result.rules[0].attributes) == 1)
    assert(result.rules[1].selector.as_str_list() == ["body"])
    assert(len(result.rules[1].attributes) == 2)


def test_cssselector_check_item():
    cssparse.enable_selector_debugging()

    assert(cssparse.CSSSelector.check_item(
        "*", ["bla"]
    ) is True)
    assert(cssparse.CSSSelector.check_item(
        ".test", ["bla"]
    ) is False)
    assert(cssparse.CSSSelector.check_item(
        ".test", ["bla"], item_classes=["test"]
    ) is True)
    assert(cssparse.CSSSelector.check_item(
        ".test.test2", ["bla"], item_classes=["test"]
    ) is False)
    assert(cssparse.CSSSelector.check_item(
        ".test", ["bla"], item_classes=["test2", "test"]
    ) is True)
    assert(cssparse.CSSSelector.check_item(
        "myitem.test1.test2", ["myitem"],
        item_classes=["test1", "test2", "test3"]
    ) is True)


def test_complex_selector_scenarios():
    cssparse.enable_selector_debugging()

    result = cssparse.parse("""
        * {padding:5px}
        body {height:15px; padding:10px;}
    """)
    attributes = result.get_item_attributes(
        "body", transform_funcs=[]
    ).attributes
    assert(set(attributes.keys()) == {"height", "padding"})
    assert(attributes["height"].value == "15px")

    result = cssparse.parse("""
        body {height:15px; padding:10px;}
        * {padding:5px}
    """)
    attributes = result.get_item_attributes(
        "body", transform_funcs=[]
    ).attributes
    assert(set(attributes.keys()) == {"height", "padding"})
    assert(attributes["height"].value == "15px")
    assert(attributes["padding"].value == "10px")

    result = cssparse.parse("""
        body {height:15px; padding:10px;}
        body {padding:5px}
    """)
    attributes = result.get_item_attributes(
        "body", transform_funcs=[]
    ).attributes
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
        "body", nondirectional_can_override_directional=True,
        transform_funcs=[],
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
        "body", nondirectional_can_override_directional=True,
        transform_funcs=[],
    ).attributes
    assert(set(attributes.keys()) == {"padding", "padding-left"})
    assert(attributes["padding-left"].value == "3px")

    result = cssparse.parse("""
        * {padding-left:5px}
        body {padding:10px;}
    """)
    attributes = result.get_item_attributes(
        "body", nondirectional_can_override_directional=False,
        transform_funcs=[],
    ).attributes
    assert(attributes["padding-left"].value == "5px")
