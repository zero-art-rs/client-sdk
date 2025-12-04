use zrt_art::{errors::ArtError, node_index::Direction};

pub struct BinaryTree<T> {
    root: Option<Box<BtNode<T>>>,
}

impl<T> BinaryTree<T> {
    /// If exists, returns reference on the node at the end of the given path form root. Else return `ArtError`.
    pub(crate) fn mut_node_at(&mut self, path: &[Direction]) -> Result<&mut BtNode<T>, ArtError> {
        let mut node = self.root.as_mut().ok_or(ArtError::EmptyArt)?.as_mut();
        for direction in path {
            if let Some(child_node) = node.mut_child(*direction) {
                node = child_node;
            } else {
                return Err(ArtError::PathNotExists);
            }
        }

        Ok(node)
    }
}

pub struct BtNode<T> {
    left: Option<Box<BtNode<T>>>,
    right: Option<Box<BtNode<T>>>,
    value: T,
}

impl<T> BtNode<T> {
    pub fn child<'a>(&'a self, child: Direction) -> Option<&'a Self> {
        match child {
            Direction::Left => self.left.as_ref().map(|boxed| boxed.as_ref()),
            Direction::Right => self.right.as_ref().map(|boxed| boxed.as_ref()),
        }
    }

    pub fn left(&self) -> Option<&Self> {
        self.child(Direction::Left)
    }

    pub fn right(&self) -> Option<&Self> {
        self.child(Direction::Right)
    }

    pub fn mut_child(&mut self, child: Direction) -> Option<&mut Self> {
        match child {
            Direction::Left => self.left.as_mut().map(|boxed| boxed.as_mut()),
            Direction::Right => self.right.as_mut().map(|boxed| boxed.as_mut()),
        }
    }

    // pub fn is_leaf(&self) -> bool {
    //     matches!(self, ArtNode::Leaf { .. })
    // }
}
