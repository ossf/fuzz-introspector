package ossf.fuzz.introspector.soot;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import soot.SceneTransformer;

public class CustomSenceTransformerTest {
  @Test
  public void testNoException() {
    assertDoesNotThrow(() -> {});
  }

  @Test
  public void testBasic() {
    CustomSenceTransformer custom = new CustomSenceTransformer("", "", "", "", "");
    assertTrue(custom instanceof SceneTransformer);
    assertTrue(custom instanceof CustomSenceTransformer);
    assertEquals(custom.getIncludeList().size(), 0);
    assertEquals(custom.getExcludeList().size(), 0);
  }

  @Test
  public void testExcludePrefix() {
    CustomSenceTransformer custom =
        new CustomSenceTransformer("", "", "abc:def:ghi", "jkl:mno:pqr", "");
    assertEquals(custom.getIncludeList().size(), 3);
    assertEquals(custom.getExcludeList().size(), 3);
    Object[] eexpected = {"jkl", "mno", "pqr"};
    Object[] iexpected = {"abc", "def", "ghi"};
    assertArrayEquals(custom.getIncludeList().toArray(), iexpected);
    assertArrayEquals(custom.getExcludeList().toArray(), eexpected);
  }
}
