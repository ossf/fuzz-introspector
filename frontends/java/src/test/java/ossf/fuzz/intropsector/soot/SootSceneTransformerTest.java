package ossf.fuzz.introspector.soot;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import soot.SceneTransformer;

public class SootSceneTransformerTest {
  @Test
  public void testNoException() {
    assertDoesNotThrow(() -> {});
  }

  @Test
  public void testBasic() {
    SootSceneTransformer custom =
        new SootSceneTransformer("", "", "ALL", "", "", "", "", "NULL", false);
    assertTrue(custom instanceof SceneTransformer);
    assertTrue(custom instanceof SootSceneTransformer);
    assertEquals(custom.getIncludeList().size(), 1);
    assertEquals(custom.getExcludeList().size(), 0);
  }

  @Test
  public void testExcludePrefix() {
    SootSceneTransformer custom =
        new SootSceneTransformer(
            "", "", "ALL", "", "abc:def:ghi", "jkl:mno:pqr", "", "NULL", false);
    assertEquals(custom.getIncludeList().size(), 4);
    assertEquals(custom.getExcludeList().size(), 3);
    Object[] eexpected = {"jkl", "mno", "pqr"};
    Object[] iexpected = {"abc", "def", "ghi", ""};
    assertArrayEquals(custom.getIncludeList().toArray(), iexpected);
    assertArrayEquals(custom.getExcludeList().toArray(), eexpected);
  }
}
